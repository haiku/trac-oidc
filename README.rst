===================================
Trac-oidc — OpenID Connect for Trac
===================================

|version| |trac versions| |build status|

***********
Description
***********

A plugin to support authentication to trac_ using the `OpenID
Connect`_ protocol.  It works with any conforming provider, including
Keycloak_, Authentik_, Dex_, and Google_.

The plugin was originally written as a partial replacement for
TracAuthOpenId_, since Google has (as of mid-June, 2015) `discontinued
support`_ for authentication using *OpenID 2.0*.  Google’s extension_
for mapping *OpenID 2.0* identifiers to *OpenID Connect* identifiers
is still supported, so sites which previously used ``TracAuthOpenId``
for authentication against Google *should* be able to switch to using
``trac-oidc`` without losing track of user’s settings and permissions.

This plugin requires Python 3 and is tested with Trac 1.6.

The distribution may be downloaded from PyPI_.
Development takes place at github_.


.. _OpenID Connect: http://openid.net/connect/
.. _trac: http://trac.edgewall.org/
.. _TracAuthOpenId: https://pypi.python.org/pypi/TracAuthOpenId
.. _Keycloak: https://www.keycloak.org/
.. _Authentik: https://goauthentik.io/
.. _Dex: https://dexidp.io/
.. _google: https://developers.google.com/identity/protocols/OpenIDConnect
.. _discontinued support: https://support.google.com/accounts/answer/6206245
.. _extension:
   https://developers.google.com/identity/protocols/OpenID2Migration#map-identifiers
.. _pypi: https://pypi.python.org/pypi/trac-oidc
.. _github: http://github.com/trac-hacks/trac-oidc/.

*****
Usage
*****

Obtain OIDC Credentials
=======================

The *redirect URI* used by this plugin is the base URL of your trac
followed by ``/trac_oidc/redirect``.  If the top of your trac is at
``https://trac.example.org``, then the *redirect URI* is
``https://trac.example.org/trac_oidc/redirect``.  Configure this exact
URI at your provider.  If trac is reachable under multiple hostnames,
or under both ``http:`` and ``https:``, you may need to register
multiple redirect URIs.

Keycloak
--------

1. In the Keycloak admin console, select your realm and create (or
   choose) a client of type **OpenID Connect**.

2. Enable **Client authentication** (this makes it a confidential
   client) and **Standard flow**.  You do not need any other flows.

3. Under **Valid redirect URIs**, add the redirect URI computed above,
   for example ``https://trac.example.org/trac_oidc/redirect``.

4. Copy the **Client ID** from the client's **Settings** tab, and the
   **Client secret** from the **Credentials** tab.

5. The issuer URL is the realm URL, for example
   ``https://keycloak.example.org/realms/myrealm``.  The plugin fetches
   ``/.well-known/openid-configuration`` from that URL to discover the
   authorization, token and userinfo endpoints.

6. Configure the plugin in ``trac.ini`` (see `Configuration`_ below).

Google (legacy)
---------------

Google can be configured the same way, using
``issuer = https://accounts.google.com``, or with a downloaded
``client_secret.json`` file.  To use the file, create *OAuth 2.0
credentials* in the `Google Developers Console`_, download the JSON
file, and save it where trac can read it.  By default the plugin looks
for ``client_secret.json`` in the ``conf`` subdirectory of the trac
environment.  (Since the file contains sensitive information, consider
setting its permissions so that not just anybody can read it.)

.. _google developers console: https://console.developers.google.com/


Install the Plugin
==================

The plugin is available from PyPI_, so it may be installed,
e.g., using pip_::

      pip install trac-oidc

.. _pip: https://pip.pypa.io/en/stable/

Configuration
=============

In your ``trac.ini``::

  [components]

  # You must enable the trac_oidc plugin
  trac_oidc.* = enabled

  # Optional: You probably want to disable the stock login module
  trac.web.auth.loginmodule = disabled

  [trac_oidc]

  # The OpenID Connect issuer.  For Keycloak this is the realm URL.
  issuer = https://keycloak.example.org/realms/myrealm

  # The client credentials from your provider.
  client_id = trac
  client_secret = 0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0

  # Optional: scopes to request.  The default is shown.
  scope = openid email profile

  # Optional: text of the login link in the metanav.
  # login_button_text = Login using Keycloak

  # Optional: how to authenticate to the token endpoint.  Keycloak's
  # default client authenticator accepts client_secret_post (the
  # default) and client_secret_basic.
  # token_auth_method = client_secret_post

  # Optional: explicit endpoint overrides.  Normally these are
  # discovered from ``issuer`` and should not be needed.
  # authorization_endpoint = https://keycloak.example.org/realms/myrealm/protocol/openid-connect/auth
  # token_endpoint = https://keycloak.example.org/realms/myrealm/protocol/openid-connect/token
  # userinfo_endpoint = https://keycloak.example.org/realms/myrealm/protocol/openid-connect/userinfo

  # Optional, for legacy Google client_secret.json configurations only.
  # The default is ``client_secret.json``.  Relative paths are
  # interpreted relative to the ``conf`` subdirectory of the trac
  # environment (i.e. alongside ``trac.ini``.)
  # client_secret_file = /path/to/client_secret.json

  # Optional: link an OpenID Connect identity to an existing Trac
  # account with the same name.  See "Linking to existing accounts"
  # below.  The default is ``no``.
  # link_existing_accounts = email

  [openid]

  # Optional: This only matters if you would like to migrate
  # users created by the TracAuthOpenId_ plugin to Google's provider.
  # In that case, the OpenID realm must be set to the same value
  # that was used by TracAuthOpenId (where it is called the *trust root*)
  # for the identity URLs to be comparable.
  #
  # If this is set, then the OpenID realm will include just the hostname,
  # otherwise the realm will include the full base path of the trac.
  # E.g. if your trac is ``http://example.org:8080/mytrac``, then the realm
  # will be ``http://example.org:8080/`` if ``absolute_trust_root`` is set
  # and ``http://example.org:8080/mytrac`` if ``absolute_trust_root`` is
  # not set.
  #
  # The default is ``true``.
  #
  absolute_trust_root = false

The login name used by trac is taken from the ``preferred_username``
claim, falling back to ``email``, then ``name``, and finally the
provider's subject identifier.  Keycloak supplies ``preferred_username``
when the ``profile`` scope is requested, so users normally log in with
their Keycloak username.

.. note::

   The ``client_secret`` is stored in ``trac.ini`` in plain text.
   Restrict access to the ``conf`` directory accordingly.

****************************
Linking to existing accounts
****************************

By default, every OpenID Connect identity gets its own Trac account.
If the provider supplies a ``preferred_username`` which is identical to
the name of an account that already exists in Trac — for instance an
account managed by the AccountManagerPlugin_ — a duplicate account is
*never* created.  Instead, unless linking is enabled and succeeds, the
login is refused with an error page asking the user to contact an
administrator.  This avoids silently creating a second account (e.g.
``joe (2)``) which would not inherit the permissions, properties or
ticket history of the existing one.

The ``link_existing_accounts`` option changes this behavior.  When it
is enabled, and the name of the identity is identical to the name of an
existing account, the OpenID Connect identity is associated with that
existing account instead of a new one being created.  The association
is remembered, so subsequent logins use the same account.

The option takes one of the following values:

``no``
   Never link.  This is the default.

``name``
   Link to the existing account with the same name.

``email``
   Link to the existing account with the same name, but only if the
   email address of the identity matches the email address stored for
   the account.  The identity provider must also assert that the email
   address is verified, using the ``email_verified`` claim.  An identity
   whose provider does not state whether the address is verified is
   never linked.

In every mode, if an account with the supplied name already exists but
cannot be linked, the login is refused with an error page.  The page
always asks the user to contact an administrator.

In ``email`` mode the address is also synchronized on every subsequent
login of an account which is already associated with an identity.  If
the address stored in Trac is later changed so that it no longer matches
the address supplied by the provider, the Trac address is updated to the
one supplied by the provider.

For example::

  [trac_oidc]
  link_existing_accounts = email

.. note::

   Linking by name alone is a security risk: anybody who is able to
   register an account with the same name at the identity provider
   takes over the existing Trac account.  This is only acceptable if
   the identity provider is strictly managed (i.e. if users cannot
   register accounts themselves).  The ``email`` mode is safer, but it
   requires that the provider supplies a verified email address, and
   that the email address stored for the Trac account is up to date.

   The ``email_verified`` claim is optional in OpenID Connect, so some
   providers do not supply it.  In the ``email`` mode such an identity is
   never linked, because the verification status of its email address is
   unknown.  A provider may supply the claim in the *userinfo* response
   rather than in the *id_token*; either is accepted.

Some further details:

* The name of the account must be *identical* to the username
  supplied by the provider.  The comparison is case-sensitive.

* An account which is already associated with a *different* OpenID
  Connect identity is never linked to.  The login fails with an error
  page instead.

* If an account with the matching name exists but cannot be linked for
  any other reason (for example, the provider does not supply a verified
  email address in ``email`` mode), the login fails with an error page
  rather than creating a duplicate account.

* The attributes of the existing account (e.g. its name and email
  address) are left alone.  They may still be administered by the
  AccountManagerPlugin.

* If no account with a matching name exists, a new one is created, as
  usual.

* Users who logged in *before* the option was enabled keep using the
  account which was created for them back then (e.g. ``joe (2)``).  To
  move such a user over to the pre-existing account, remove the
  ``trac_oidc.subject`` session attribute from their account; the next
  login will then link them to the account with the matching name.

*****************************
Migration from TracAuthOpenId
*****************************

If you used **only** Google as the authentication provider with
TracAuthOpenId_, then you should be able to disable
``TracAuthOpenId``, configure and enable ``trac-oidc``, and things
*should* just work — users should keep their sessions (i.e. they will
retain their settings and permissions.)

.. note::

   Make sure not to change the setting of ``absolute_trust_root`` from
   whatever you were using with ``TracAuthOpenId``.

If you were using multiple authentication providers with ``TracAuthOpenId``,
it should be possible to run both ``TracAuthOpenId`` (with Google disabled),
and ``trac-oidc`` together.  I have not tried this, however, and some tuning
will probably be required.

*****
To Do
*****

Possible improvements.

Integrate with AccountManagerPlugin
===================================

I’m not sure exactly what’s involved, but it would be nice if the
AccountManagerPlugin_ could be used to administer associations between
OIDC subject identifiers and authenticated sessions, etc.

Note that the ``link_existing_accounts`` option (see `Linking to existing
accounts`_) allows an OpenID Connect identity to take over an account
managed by the AccountManagerPlugin_.  Since the AccountManagerPlugin
stores its accounts as trac sessions, the association is made by adding
the ``trac_oidc.subject`` session attribute to the existing session.

.. _AccountManagerPlugin: https://trac-hacks.org/wiki/AccountManagerPlugin

*******
Authors
*******

`Jeff Dairiki`_

.. _Jeff Dairiki: mailto:dairiki@dairiki.org

.. |version| image::
    https://img.shields.io/pypi/v/trac-oidc.svg
    :target: https://pypi.python.org/pypi/trac-oidc/
    :alt: Latest Version
.. |build status| image::
    https://travis-ci.org/trac-hacks/trac-oidc.svg?branch=master
    :target: https://travis-ci.org/trac-hacks/trac-oidc
.. |trac versions| image::
   https://img.shields.io/badge/trac-1.4%2C%201.6-blue.svg
   :target: http://trac.edgewall.org/
