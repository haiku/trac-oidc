# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
""" A plugin to support trac authentication using an *OpenID Connect*
provider (Keycloak, Google, Authentik, ...).

"""
from __future__ import absolute_import

from contextlib import contextmanager
from itertools import chain, count
import os
from urllib.parse import urlencode, urlsplit

from trac.admin.api import IAdminPanelProvider
from trac.config import BoolOption, Option, PathOption
from trac.core import implements, Component, ExtensionPoint, TracError
from trac.perm import PermissionSystem
from trac.util.html import tag
from trac.util.translation import _
from trac.web.api import IAuthenticator, IRequestHandler
from trac.web.auth import LoginModule
from trac.web.chrome import (add_notice, add_warning, INavigationContributor,
                             ITemplateProvider)
from trac.web.session import DetachedSession

from .api import ILoginManager
from .authenticator import (
    Authenticator,
    AuthenticationError,
    AuthenticationFailed,
    DEFAULT_SCOPE,
    client_secrets_from_file,
    )
from .compat import db_query, is_component_enabled, logout_link


class AccountLinkError(TracError):
    """An OpenID Connect identity could not be linked to an existing
    Trac account.

    Creating a new account in this situation would silently produce a
    duplicate (for example, ``joe (2)``), so the login is refused and the
    user is told to contact an administrator instead.
    """


class EmailMismatchError(AccountLinkError):
    """The email address of an OIDC identity does not match the email
    address of the existing Trac account it is being linked to.

    This is raised (rather than silently creating a second account) when
    ``link_existing_accounts`` is set to ``email`` and an account with a
    matching name exists, but the addresses differ.
    """


class OidcPlugin(Component):
    """ Authenticate via OpenID Connect

    """
    implements(INavigationContributor, IRequestHandler)

    RETURN_URL_SKEY = 'trac_oidc.return_url'

    client_secret_file = PathOption(
        'trac_oidc', 'client_secret_file', 'client_secret.json',
        """Path to a Google-style ``client_secret.json`` file.  Relative
        paths are interpreted relative to the ``conf`` subdirectory of
        the trac environment.  This is only needed for backwards
        compatibility; Keycloak and other providers can be configured
        entirely with the options below.""")

    issuer = Option(
        'trac_oidc', 'issuer', '',
        """The OpenID Connect issuer URL.  For Keycloak this is the realm
        URL, e.g. ``https://keycloak.example.com/realms/myrealm``.
        When set, the provider's discovery document is used to find the
        authorization, token and userinfo endpoints.""")

    client_id = Option(
        'trac_oidc', 'client_id', '',
        """The OIDC client identifier (the *Client ID* in Keycloak).""")

    client_secret = Option(
        'trac_oidc', 'client_secret', '',
        """The OIDC client secret (the *Client Secret* in Keycloak).
        Not required for public clients.""")

    scope = Option(
        'trac_oidc', 'scope', DEFAULT_SCOPE,
        """Space-separated list of OIDC scopes to request.""")

    authorization_endpoint = Option(
        'trac_oidc', 'authorization_endpoint', '',
        """Explicit authorization endpoint URL.  Normally discovered from
        ``issuer``; set this only if discovery is not available.""")

    token_endpoint = Option(
        'trac_oidc', 'token_endpoint', '',
        """Explicit token endpoint URL.  Normally discovered from
        ``issuer``; set this only if discovery is not available.""")

    userinfo_endpoint = Option(
        'trac_oidc', 'userinfo_endpoint', '',
        """Explicit userinfo endpoint URL.  This is used to fill in
        profile claims which are not present in the id_token.  Normally
        discovered from ``issuer``.""")

    token_auth_method = Option(
        'trac_oidc', 'token_auth_method', 'client_secret_post',
        """How to authenticate to the token endpoint.  One of
        ``client_secret_post``, ``client_secret_basic`` or ``none``.""")

    login_button_text = Option(
        'trac_oidc', 'login_button_text', 'Login using OpenID Connect',
        """Text of the login link shown in the metanav.""")

    registration_url = Option(
        'trac_oidc', 'registration_url', '',
        """URL of the identity provider's account registration page.

        When set, a *Register* link is shown in the metanav for users who
        are not logged in.  The link is not shown when this option is
        empty.""")

    register_button_text = Option(
        'trac_oidc', 'register_button_text', 'Register',
        """Text of the registration link shown in the metanav.""")

    openid_realm = Option(
        'trac_oidc', 'openid_realm', '',
        """Google-only OpenID 2.0 realm, used when migrating accounts from
        the TracAuthOpenId plugin.  Leave empty for Keycloak.""")

    # deprecated
    absolute_trust_root = BoolOption(
        'openid', 'absolute_trust_root', 'true',
        """Whether we should use absolute trust root or by project.""")

    login_managers = ExtensionPoint(ILoginManager)

    def __init__(self):
        # We should show our own "Logout" link only if the stock
        # LoginModule is disabled.
        self.show_logout_link = not is_component_enabled(self.env, LoginModule)

        self.userdb = UserDatabase(self.env)

    # INavigationContributor methods

    def get_active_navigation_item(self, req):
        return 'trac_oidc.login'

    def get_navigation_items(self, req):
        oidc_href = req.href.trac_oidc
        path_qs = req.path_info
        if req.query_string:
            path_qs += '?' + req.query_string

        if not req.authname or req.authname == 'anonymous':
            # Not logged in, show login link
            login_link = tag.a(_(self.login_button_text),
                               href=oidc_href('login', return_to=path_qs))
            yield 'metanav', 'trac_oidc.login', login_link
            if self.registration_url:
                yield ('metanav', 'trac_oidc.register',
                       tag.a(_(self.register_button_text),
                             href=self.registration_url))

        elif self.show_logout_link:
            # Logged in and LoginModule is disabled, show logout link
            yield ('metanav', 'trac_oidc.login',
                   _('logged in as %(user)s', user=req.authname))
            yield ('metanav', 'trac_oidc.logout',
                   logout_link(oidc_href, return_to=path_qs))

    # IRequestHandler methods

    def match_request(self, req):
        path_info = req.path_info
        if path_info == '/login' and self.show_logout_link:
            # Stock LoginModule is disabled, so handle default /login too
            return True
        return path_info in ('/trac_oidc/login',
                             '/trac_oidc/logout',
                             '/trac_oidc/redirect')

    def process_request(self, req):
        if req.path_info.endswith('/logout'):
            return_url = self._get_return_url(req)
            self._forget_user(req)
            return req.redirect(return_url)
        elif req.path_info.endswith('/login'):
            # Start the login process by redirectory to OP
            req.session[self.RETURN_URL_SKEY] = self._get_return_url(req)
            authenticator = self._get_authenticator(req)
            return req.redirect(authenticator.get_auth_url(req))
        elif req.path_info.endswith('/redirect'):
            # Finish the login process after redirect from OP
            return_url = req.session.pop(self.RETURN_URL_SKEY, req.abs_href())
            id_token = self._retrieve_id(req)
            if id_token:
                authname = self._find_or_create_session(req, id_token)
                assert authname
                self.log.debug("Logging in as %r", authname)
                self._remember_user(req, authname)
            return req.redirect(return_url)

    # private methods

    def _retrieve_id(self, req):
        """ Retrieve oidc id_token from provider.

        Returns ``None`` if authentication was unsuccessful for any reason.

        """
        authenticator = self._get_authenticator(req)
        try:
            return authenticator.get_identity(req)
        except AuthenticationFailed as ex:
            self.log.info("Authentication failed: %s", ex)
            add_warning(req, "Authentication failed: %s", ex)
        except AuthenticationError as ex:
            self.log.error("Authentication error: %s", ex)
            add_warning(req, "Authentication error: %s", ex)

    def _find_or_create_session(self, req, id_token):
        """ Find or create authenticated session for subject.
        """
        userdb = self.userdb
        authname = userdb.find_session(id_token)
        if not authname:
            # There is no authenticated session for the user.  The
            # identity may be linked to an existing account (e.g. one
            # managed by the AccountManagerPlugin) with a matching name.
            authname = userdb.link_session(id_token)
            if authname:
                add_notice(req, _(
                    "Your OpenID Connect account has been linked to your "
                    "existing Trac account '%(authname)s'.",
                    authname=authname))
        if not authname:
            # There is no authenticated session for the user,
            # create a new one
            # XXX: should it be configurable whether this happens?
            authname = userdb.create_session(id_token)
            add_notice(req, _(
                "Hello! You appear to be new here. "
                "A new authenticated session with "
                "username '%(authname)s' has been created for you.",
                authname=authname))
        return authname

    def _remember_user(self, req, authname):
        for lm in self.login_managers:
            lm.remember_user(req, authname)

    def _forget_user(self, req):
        for lm in self.login_managers:
            lm.forget_user(req)

    def _get_authenticator(self, req):
        redirect_url = req.abs_href.trac_oidc('redirect')

        client_id = self.client_id or None
        client_secret = self.client_secret or None
        issuer = self.issuer or None
        authorization_endpoint = self.authorization_endpoint or None
        token_endpoint = self.token_endpoint or None
        userinfo_endpoint = self.userinfo_endpoint or None

        # Fall back to the legacy Google-style client_secret.json file
        # for any values which were not configured explicitly.
        secret_file = self.client_secret_file
        if secret_file and os.path.exists(secret_file):
            secrets = client_secrets_from_file(secret_file)
            client_id = client_id or secrets['client_id']
            client_secret = client_secret or secrets['client_secret']
            issuer = issuer or secrets['issuer']
            authorization_endpoint = (authorization_endpoint
                                      or secrets['authorization_endpoint'])
            token_endpoint = token_endpoint or secrets['token_endpoint']
            userinfo_endpoint = (userinfo_endpoint
                                 or secrets['userinfo_endpoint'])

        if not client_id:
            raise TracError(
                "OpenID Connect is not configured.  Set [trac_oidc] issuer, "
                "client_id and client_secret in trac.ini (or provide the "
                "legacy client_secret_file).")

        openid_realm = self._get_openid_realm(req)
        self.log.debug('OIDC issuer = %r, openid_realm = %r',
                       issuer, openid_realm)
        return Authenticator(
            redirect_url, client_id,
            client_secret=client_secret,
            issuer=issuer,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            scope=self.scope,
            openid_realm=openid_realm,
            token_auth_method=self.token_auth_method,
            log=self.log)

    def _get_openid_realm(self, req):
        """ Get the OpenID realm.

        This computes the OpenID realm in exactly the same manner
        that the ``TracAuthOpenID`` plugin does.

        Note that I'm not sure this is really the “right” way to do it,
        but, since we want to get back the same identity URLs from google
        as we did using ``TracAuthOpenID``, here we are.

        """
        if self.openid_realm:
            return self.openid_realm
        if self.issuer and 'google' not in self.issuer.lower():
            # The openid.realm parameter is a Google extension.  Do not
            # send unknown parameters to other providers such as Keycloak.
            return None

        href = req.href()
        abs_href = self.env.abs_href()
        if href and abs_href.endswith(href):
            base_url = abs_href[:-len(href)]
        else:                   # pragma: NO COVER
            base_url = abs_href

        if self.absolute_trust_root:
            path = '/'
        else:
            path = href
        return base_url + path

    @staticmethod
    def _get_return_url(req):
        return_to = req.args.getfirst('return_to', '/')
        # We expect return_to to be a URL relative to the trac's base_path.
        # Be paranoid about this.
        scheme, netloc, path, query, anchor = urlsplit(return_to)
        if scheme or netloc or '..' in path.split('/') or anchor:
            # return url looks suspicious, ignore it.
            return req.abs_href()
        return_url = req.abs_href(path)
        if query:
            return_url += '?' + query
        return return_url


class TracOidcAdminPanel(Component):
    """Administration panels for managing OIDC account associations."""

    implements(IAdminPanelProvider, ITemplateProvider)

    def __init__(self):
        self.helper = SessionHelper(self.env)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if 'TRAC_ADMIN' in req.perm('admin', 'trac_oidc/email'):
            yield ('trac_oidc', _("TracOIDC"), 'email',
                   _("Fix Email Address"))
        if 'TRAC_ADMIN' in req.perm('admin', 'trac_oidc/unlink'):
            yield ('trac_oidc', _("TracOIDC"), 'unlink',
                   _("Unlink SSO Identity"))

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm(cat, page).require('TRAC_ADMIN')

        if page == 'unlink':
            return self._render_unlink(req, cat, page)

        username = ''
        new_email = ''
        if req.method == 'POST':
            username = (req.args.get('username') or '').strip()
            new_email = (req.args.get('email') or '').strip()
            if not username:
                add_warning(req, _("Username is required."))
            elif not new_email:
                add_warning(req, _("New email address is required."))
            elif not self.helper.account_exists(username):
                add_warning(req, _("User '%(username)s' does not exist.",
                                   username=username))
            else:
                ds = DetachedSession(self.env, username)
                ds['email'] = new_email
                ds.save()
                self.log.info(
                    "Administrator %s changed the email address of %r to %s",
                    req.authname, username, new_email)
                add_notice(req, _(
                    "Email address for '%(username)s' updated to "
                    "'%(email)s'.", username=username, email=new_email))
                req.redirect(req.href.admin(cat, page))

        return 'admin_trac_oidc.html', {
            'username': username,
            'new_email': new_email,
            }

    def _render_unlink(self, req, cat, page):
        username = ''
        if req.method == 'POST':
            username = (req.args.get('username') or '').strip()
            if not username:
                add_warning(req, _("Username is required."))
            elif not self.helper.account_exists(username):
                add_warning(req, _("User '%(username)s' does not exist.",
                                   username=username))
            else:
                ds = DetachedSession(self.env, username)
                if UserDatabase.SUBJECT_SKEY in ds:
                    del ds[UserDatabase.SUBJECT_SKEY]
                    ds.save()
                    self.log.info(
                        "Administrator %s unlinked the SSO identity from %r",
                        req.authname, username)
                    add_notice(req, _(
                        "SSO identity unlinked from '%(username)s'.  The "
                        "identity will be linked again on the next login if "
                        "automatic linking is enabled.", username=username))
                    req.redirect(req.href.admin(cat, page))
                else:
                    add_warning(req, _(
                        "User '%(username)s' does not have an SSO identity "
                        "linked.", username=username))

        return 'admin_trac_oidc_unlink.html', {'username': username}

    # ITemplateProvider methods

    def get_htdocs_dirs(self):
        return []

    def get_templates_dirs(self):
        return [os.path.join(os.path.dirname(__file__), 'templates')]


class AuthCookieManager(LoginModule):
    """Manage the authentication cookie.

    This handles setting the trac authentication cookie and updating
    the ``auth_cookie`` table in the trac db.

    XXX: We use the stock ``trac.web.auth.LoginModule`` to do this,
    however, as you can see, this takes a bit of hacking...

    """
    implements(IAuthenticator, ILoginManager)

    # ILoginManager methods

    def remember_user(self, req, authname):
        with _temporary_environ(req, REMOTE_USER=authname):
            self._do_login(req)  # LoginModule._do_login

    def forget_user(self, req):
        # HACK: In trac >= 1.0.2, LoginModule._do_logout does nothing
        # unless request.method == POST.
        with _temporary_environ(req, REQUEST_METHOD='POST'):
            self._do_logout(req)

    # More hackage: override INavigationContributor and
    # IRequestHandler methods inherited from LoginModule.

    def get_active_navigation_item(self, req):
        pass

    def get_navigation_items(self, req):
        return ()

    def match_request(self, req):
        return False

    def process_request(self, req):
        pass                    # pragma: NO COVER


@contextmanager
def _temporary_environ(req, **kwargs):
    """ A context manager used to teporarily modify ``req.environ``.
    """
    environ = req.environ
    req.environ = environ.copy()
    req.environ.update(kwargs)
    try:
        yield req.environ
    finally:
        req.environ = environ


class UserDatabase(Component):
    """Code to map OpenID identities to trac authnames.

    """
    abstract = True

    SUBJECT_SKEY = 'trac_oidc.subject'
    IDENTITY_URL_SKEY = 'openid_session_identity_url_data'

    # Names which are reserved by trac itself.
    RESERVED_AUTHNAMES = ('anonymous', 'authenticated')

    link_existing_accounts = Option(
        'trac_oidc', 'link_existing_accounts', 'no',
        """Whether an OpenID Connect identity may be linked to an existing
        Trac account (e.g. an account managed by the AccountManagerPlugin)
        whose name is identical to the username supplied by the identity
        provider.

        One of:

        ``no``
            Never link.  A new account is created for every identity which
            is not already associated with a Trac session, unless an
            account with the supplied name already exists.  In that case
            the login is refused with an error page.  This is the default.
        ``name``
            Link to the existing account with the matching name.
        ``email``
            Link to the existing account with the matching name, but only
            if the email address of the identity matches the email address
            stored for the account.  The identity provider must also
            assert that the email address is verified, by means of the
            ``email_verified`` claim.  An identity whose provider does not
            state whether the address is verified is never linked.

        In every mode, if an account with the supplied name already exists
        but cannot be linked to the identity, the login is refused and an
        error page is shown.  A duplicate account such as ``joe (2)`` is
        never created.

        In ``email`` mode the address is also synchronized on every
        subsequent login of an already-associated account.  If the
        address stored in Trac later changes and no longer matches the
        one supplied by the identity provider, the Trac address is
        updated from the identity provider.

        .. note::

           Linking by name alone allows anybody who can register an
           account with the same name at the identity provider to take
           over the existing Trac account.  The ``email`` mode is safer,
           but it requires that the provider supplies an email address,
           that the provider asserts that the address is verified, and
           that the email address stored for the Trac account is up to
           date.
        """)

    def __init__(self):
        self.helper = SessionHelper(self.env)

    def _authname(self, name):
        """Return the login name that Trac will actually use for *name*.

        When the ``[trac] ignore_auth_case`` option is enabled, Trac's
        ``LoginModule`` lower-cases login names before authenticating
        them (see ``LoginModule._do_login``).  The name supplied by the
        identity provider must be normalized in exactly the same way;
        otherwise an identity named ``Admin`` would be checked against
        (and might create) a session called ``Admin`` even though Trac
        would then authenticate it as the existing account ``admin``.

        """
        if self.env.config.getbool('trac', 'ignore_auth_case', False):
            return name.lower()
        return name

    def find_session(self, id_token):
        """ Find existing authenticated session corresponding to identity.

        Returns the session id, or ``None`` if no corresponding authenticated
        session is found.

        """
        iss, sub = id_token['iss'], id_token['sub']
        # openid_id is a Google-only claim used to migrate accounts
        # created by TracAuthOpenId.  Avoid triggering a userinfo
        # request for other providers such as Keycloak.
        identity_url = id_token.get('openid_id') if 'google' in iss else None

        authname = self.find_session_by_oidc_subject(iss, sub)
        if authname:
            self._sync_email(id_token, authname)
            return authname
        if identity_url:
            # Fallback to using the OpenIDv2 identity URL which
            # (may have) been set by the ``TracAuthOpenId`` plugin
            authname = self.find_session_by_openid_id(identity_url)
            if authname:
                self._sync_email(id_token, authname)
                self.log.info(
                    "Claiming session %s with oid identity %s for (%s, %s)",
                    authname, identity_url, iss, sub)
                self.associate_session(authname, iss, sub)
        return authname

    def create_session(self, id_token):
        """ Create a brand new authenticated session for identity

        """
        subject_id = self.subject_uri(id_token['iss'], id_token['sub'])
        preferred_username = self._authname(
            self.preferred_username(id_token))
        if preferred_username in self.RESERVED_AUTHNAMES:
            self.log.error(
                "Not creating a new account for the OpenID Connect identity "
                "(%s): the username %r is reserved by trac.",
                subject_id, preferred_username)
            raise AccountLinkError(_(
                "The username '%(authname)s' supplied by your OpenID "
                "Connect provider is reserved by Trac. Please contact an "
                "administrator for assistance.", authname=preferred_username))
        if self.helper.account_exists(preferred_username):
            # Creating a new session here would silently create a
            # duplicate account such as ``joe (2)``.  Refuse instead.
            self.log.error(
                "Not creating a new account for the OpenID Connect identity "
                "(%s): an account named %r already exists and the identity "
                "could not be linked to it.", subject_id, preferred_username)
            raise self._account_exists_error(preferred_username)
        attributes = {self.SUBJECT_SKEY: subject_id}
        attributes.update(self.default_attributes(id_token))
        authname = self.helper.create_session(preferred_username, attributes)
        self.log.info(
            "Created new authenticated session for %s with attributes %r",
            authname, attributes)
        return authname

    def link_session(self, id_token):
        """ Link the identity to an existing account with a matching name.

        The name of the account must be identical to the username
        provided by the identity provider.  Whether linking is done at
        all (and under which conditions) is controlled by the
        ``link_existing_accounts`` option.

        Returns the authname of the account to which the identity was
        linked, or ``None`` if no account with a matching name exists.

        Raises :class:`AccountLinkError` if an account with a matching
        name exists but the identity cannot be linked to it.  (Creating a
        new account in that case would silently produce a duplicate such
        as ``joe (2)``.)

        """
        mode = (self.link_existing_accounts or 'no').strip().lower()
        if mode not in ('name', 'email') and mode != 'no':
            self.log.error(
                "Invalid value %r for the link_existing_accounts option;"
                " expected one of 'no', 'name' or 'email'.",
                self.link_existing_accounts)
            mode = 'no'

        authname = self._authname(self.preferred_username(id_token))
        if authname in self.RESERVED_AUTHNAMES:
            self.log.error(
                "Not linking the OpenID Connect identity to the account %r: "
                "that name is reserved by trac.", authname)
            return None
        if not self.helper.account_exists(authname):
            # No account with that name exists (yet).
            return None

        if mode == 'no':
            self.log.error(
                "Not creating a new account for the OpenID Connect identity: "
                "an account named %r already exists, but "
                "link_existing_accounts is disabled.", authname)
            raise self._account_exists_error(authname)

        subject_id = self.subject_uri(id_token['iss'], id_token['sub'])
        linked_subject = self.helper.get_session_attribute(
            authname, self.SUBJECT_SKEY)
        if linked_subject and linked_subject != subject_id:
            # Never take over an account which is already associated
            # with a different identity.
            self.log.error(
                "Not linking the OpenID Connect identity (%s) to the "
                "existing account %r: that account is already associated "
                "with another identity (%s).",
                subject_id, authname, linked_subject)
            raise self._account_exists_error(authname)

        if mode == 'email' and not self._email_matches(id_token, authname):
            raise self._account_exists_error(authname)

        self.associate_session(authname, id_token['iss'], id_token['sub'])
        self.log.info(
            "Linked the OpenID Connect identity (%s) to the existing "
            "account %r.", subject_id, authname)
        return authname

    @staticmethod
    def _account_exists_error(authname):
        return AccountLinkError(_(
            "An account named '%(authname)s' already exists in Trac, "
            "but your OpenID Connect identity could not be linked to "
            "it. Please contact an administrator for assistance.",
            authname=authname))

    def _sync_email(self, id_token, authname):
        """Keep the account email in sync with the identity provider.

        When ``link_existing_accounts`` is ``email``, the address of the
        identity is authoritative for an account which is already
        associated with that identity.  If the address stored in Trac
        differs (for example because the user changed it under
        preferences), update it to the address supplied by the provider.
        """
        mode = (self.link_existing_accounts or 'no').strip().lower()
        if mode != 'email':
            return
        email = id_token.get('email')
        if not email:
            # The provider does not expose an address.  Leave the
            # account as it is.
            return
        email = email.strip()
        account_email = self.helper.get_session_attribute(authname, 'email')
        if account_email and account_email.strip().lower() == email.lower():
            return
        ds = DetachedSession(self.env, authname)
        ds['email'] = email
        ds.save()
        self.log.info(
            "Updated the email address of the existing account %r to %s "
            "from the OpenID Connect identity.", authname, email)

    def _email_matches(self, id_token, authname):
        """ Check that the email address of the identity matches the one
        stored for the account.

        """
        email = id_token.get('email')
        if not email:
            self.log.error(
                "Not linking the OpenID Connect identity to the existing "
                "account %r: the identity does not provide an email "
                "address.", authname)
            return False
        verified = id_token.get('email_verified')
        if verified is None:
            # The provider did not tell us whether the email address is
            # verified.  Per OpenID Connect Core 5.1.1 the value is
            # unknown in that case, so the address must not be treated as
            # verified.
            self.log.error(
                "Not linking the OpenID Connect identity to the existing "
                "account %r: the identity does not state whether its email "
                "address (%s) is verified.", authname, email)
            return False
        if str(verified).lower() not in ('true', '1'):
            self.log.error(
                "Not linking the OpenID Connect identity to the existing "
                "account %r: the email address of the identity (%s) is not "
                "verified.", authname, email)
            return False
        account_email = self.helper.get_session_attribute(authname, 'email')
        if not account_email:
            self.log.error(
                "Not linking the OpenID Connect identity to the existing "
                "account %r: the account does not have an email address.",
                authname)
            return False
        if account_email.strip().lower() != email.strip().lower():
            self.log.error(
                "Not linking the OpenID Connect identity to the existing "
                "account %r: the email address of the identity (%s) does "
                "not match the email address of the account (%s).",
                authname, email, account_email)
            raise self._email_mismatch_error()
        return True

    @staticmethod
    def _email_mismatch_error():
        return EmailMismatchError(_(
            "The account you are logging into has a misaligned email "
            "address between what is known to Trac, and what is "
            "configurd within our OIDC provider.  Please contact an "
            "administrator for assistance"))

    def find_session_by_oidc_subject(self, iss, sub):
        subject_id = self.subject_uri(iss, sub)
        sids = self.helper.find_session_by_attr(self.SUBJECT_SKEY, subject_id)
        if len(sids) > 1:
            self.log.warning(
                "Multiple users share the same oidc iss=%r, sub=%r: %s",
                iss, sub, ', '.join(map(repr, sids)))
        return sids[0] if sids else None

    def find_session_by_openid_id(self, openid_id):
        sids = self.helper.find_session_by_attr(self.IDENTITY_URL_SKEY,
                                                openid_id)
        if len(sids) > 1:
            self.log.warning(
                "Multiple users share the same openid url %s: %s",
                openid_id, ', '.join(map(repr, sids)))
        return sids[0] if sids else None

    def associate_session(self, authname, iss, sub):
        ds = DetachedSession(self.env, authname)
        ds[self.SUBJECT_SKEY] = self.subject_uri(iss, sub)
        ds.save()

    @staticmethod
    def preferred_username(id_token):
        """Get the preferred username for the user.
        """
        sub = id_token['sub']
        assert sub
        return (
            id_token.get('preferred_username')
            or id_token.get('email')
            or id_token.get('name')
            or sub)

    @staticmethod
    def default_attributes(id_token):
        """Get extra attributes to be set on newly created sessions.
        """
        return {
            'name': id_token.get('name', ''),
            'email': id_token.get('email', ''),
            }

    @staticmethod
    def subject_uri(iss, sub):
        """Return a subject identifier.

        The subject identifier is a single string which combines the
        issuer (``iss``) and subject (``sub``) from the OpenID Connect
        id_token.

        Note that, AFAIK, this method of combining ``iss`` and ``sub``
        into a single string is not in any specification — I just made it
        up.

        """
        if '://' not in iss:
            # Normalize google's iss. See
            # http://openid.net/specs/openid-connect-core-1_0.html#GoogleIss
            iss = 'https://%s' % iss
        query_string = urlencode({'sub': sub})
        return '%s?%s' % (iss, query_string)


class SessionHelper(Component):
    """Helper for searching/manipulating the user database.

    Note that in trac, the user account/profile database is
    implemented as part of the session state storage.  User accounts
    are refered to as "authenticated sessions".  The “username” is
    referred to as the *session id* or ``sesssion.sid``.  It is also
    called the *authname* (e.g. ``req.authname``.)

    """
    abstract = True

    def __init__(self):
        self.permissions = PermissionSystem(self.env)

    def find_session_by_attr(self, attr_name, attr_value):
        """ Find an authenticated session which contain a specific attribute.

        """
        rows = db_query(self.env,
                        "SELECT session.sid"
                        " FROM session"
                        " INNER JOIN session_attribute AS attr"
                        "                  USING(sid, authenticated)"
                        " WHERE session.authenticated=%s"
                        "       AND attr.name=%s AND attr.value=%s"
                        " ORDER BY session.last_visit DESC",
                        (1, attr_name, attr_value))
        return [row[0] for row in rows]

    def session_exists(self, authname):
        """ Return True if an authenticated session with this sid exists.

        """
        for _ in db_query(self.env,
                          "SELECT 1 FROM session"
                          " WHERE sid=%s AND authenticated=1",
                          (authname,)):
            return True
        return False

    def account_exists(self, authname):
        """ Return True if an account with this name already exists.

        An account is either an authenticated session with the given
        session id, or a name which has been granted permissions.

        """
        return (self.session_exists(authname)
                or self.permission_exists_for(authname))

    def get_session_attribute(self, authname, attr_name):
        """ Return the value of an attribute of an authenticated session.

        Returns ``None`` if the session does not exist, or if it does not
        have such an attribute.

        """
        for row in db_query(self.env,
                            "SELECT value FROM session_attribute"
                            " WHERE sid=%s AND authenticated=1 AND name=%s",
                            (authname, attr_name)):
            return row[0]
        return None

    def create_session(self, authname_base, attributes):
        """Create a new authenticated session.

        (In trac, authenticated sessions are, essentially “user accounts”,
        so this creates a new account or “login” on the trac.)

        If possible, the session is created with an ``sid`` of
        ``authname_base``.  If a session already exists with that
        ``sid``, then a suffix is added to make the ``sid`` unique.

        The attributes of the new session are initialized from the
        ``attributes`` argument, if any.

        The ``sid`` of the new session is returned.

        """
        if not attributes:
            raise ValueError("Attributes required for new session")

        for suffix in self.uniquifier_suffixes():
            authname = authname_base + suffix
            if self.permission_exists_for(authname):
                continue
            ds = DetachedSession(self.env, authname)
            # At least in 0.12.2, this means no session exists.
            is_new = ds.last_visit == 0 and len(ds) == 0
            if is_new:
                break
        for key, value in attributes.items():
            ds[key] = value or ''
        ds.save()
        return authname

    def uniquifier_suffixes(self):
        """ Suffixes used to generate unique authnames.
        """
        return chain([""], (" (%d)" % n for n in count(2)))

    def permission_exists_for(self, authname):
        return any(authname == user
                   for user, perm in self.permissions.get_all_permissions())
