# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""
OpenID Connect / OAuth 2.0 authentication helpers.

This module implements the *authorization code* flow using only the
Python standard library, so that it can talk to any conforming OpenID
Connect provider (Keycloak, Google, Authentik, Dex, ...) instead of
being tied to Google's endpoints and client-secret file format.
"""
from __future__ import absolute_import

import base64
from functools import partial
import json
import logging
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from trac.core import TracError
from trac.util import hex_entropy

from .util import DeferredMapping, strings_differ


DEFAULT_SCOPE = 'openid email profile'
USER_AGENT = 'trac-oidc'

# Cache discovery documents for the lifetime of the process.  Login is
# infrequent and the document rarely changes, but fetching it on every
# login would add an unnecessary round-trip to the provider.
_discovery_cache = {}


class AuthenticationFailed(TracError):
    """ Authentication failed.

    Access was denied by the OpenID Provider.

    """


class AuthenticationError(TracError):
    """ Authentication error.

    An error occurred during authentication.

    """


def _http_request(url, data=None, headers=None, timeout=10):
    """Perform an HTTP request and return ``(status, body)``.

    HTTP error responses are returned rather than raised; transport
    errors are turned into :class:`AuthenticationError`.
    """
    request = Request(url, data=data, headers=headers or {})
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except HTTPError as ex:
        return ex.code, ex.read()
    except URLError as ex:
        raise AuthenticationError(
            "Unable to contact OpenID Provider: %s" % ex.reason)
    except OSError as ex:
        raise AuthenticationError(
            "Unable to contact OpenID Provider: %s" % ex)


def _json_response(url, data=None, headers=None, timeout=10):
    """Perform an HTTP request and decode a JSON response."""
    status, body = _http_request(url, data=data, headers=headers,
                                 timeout=timeout)
    try:
        text = body.decode('utf-8')
    except (AttributeError, UnicodeDecodeError):
        text = body if isinstance(body, str) else repr(body)

    try:
        data = json.loads(text)
    except ValueError:
        if status < 200 or status >= 300:
            raise AuthenticationError(
                "OpenID Provider returned HTTP %d for %s: %s"
                % (status, url, text.strip()))
        raise AuthenticationError(
            "OpenID Provider returned an invalid JSON response for %s: %s"
            % (url, text.strip()))

    if status < 200 or status >= 300:
        if isinstance(data, dict) and data.get('error'):
            description = data.get('error_description')
            raise AuthenticationError(
                "OpenID Provider returned an error: %s%s"
                % (data['error'],
                   ': ' + description if description else ''))
        raise AuthenticationError(
            "OpenID Provider returned HTTP %d for %s: %s"
            % (status, url, text.strip()))
    return data


def discover(issuer, timeout=10):
    """Fetch and cache an OpenID Connect discovery document."""
    issuer = issuer.rstrip('/')
    if issuer not in _discovery_cache:
        url = issuer + '/.well-known/openid-configuration'
        document = _json_response(
            url, headers={'Accept': 'application/json'}, timeout=timeout)
        if not document.get('authorization_endpoint') \
                or not document.get('token_endpoint'):
            raise AuthenticationError(
                "OpenID discovery document at %s is missing required "
                "endpoints" % url)
        _discovery_cache[issuer] = document
    return _discovery_cache[issuer]


def clear_discovery_cache():
    """Clear the process-wide discovery cache (mainly for tests)."""
    _discovery_cache.clear()


def client_secrets_from_file(path):
    """Load client credentials from a JSON file.

    Both Google-style ``{"web": {...}}`` / ``{"installed": {...}}``
    files and a flat mapping with the same keys are accepted.  The
    returned dictionary uses the generic OIDC endpoint names.
    """
    try:
        with open(path) as fp:
            data = json.load(fp)
    except (IOError, OSError) as ex:
        raise TracError("Unable to read OIDC client secrets file %s: %s"
                        % (path, ex))
    except ValueError as ex:
        raise TracError("Invalid JSON in OIDC client secrets file %s: %s"
                        % (path, ex))

    for key in ('web', 'installed'):
        if key in data:
            data = data[key]
            break

    def get(*names):
        for name in names:
            if data.get(name):
                return data[name]
        return None

    client_id = get('client_id')
    if not client_id:
        raise TracError(
            "OIDC client secrets file %s does not contain a client_id"
            % path)

    return {
        'client_id': client_id,
        'client_secret': get('client_secret'),
        'issuer': get('issuer'),
        'authorization_endpoint': get('authorization_endpoint', 'auth_uri'),
        'token_endpoint': get('token_endpoint', 'token_uri'),
        'userinfo_endpoint': get('userinfo_endpoint', 'userinfo_uri'),
    }


def decode_id_token(token):
    """Decode the claims from a JWT id_token.

    The signature is not verified here.  The token is obtained directly
    from the provider's token endpoint over TLS using the client
    credentials, which is the trust model used by the previous
    oauth2client-based implementation.  Issuer, audience, expiry and
    nonce claims are validated by :class:`Authenticator`.
    """
    try:
        header, payload, signature = token.split('.')
    except (AttributeError, ValueError):
        raise AuthenticationError("Malformed id_token returned by provider")

    padding = '=' * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode((payload + padding).encode('ascii'))
        return json.loads(decoded.decode('utf-8'))
    except (TypeError, ValueError, UnicodeDecodeError):
        raise AuthenticationError("Unable to decode id_token returned by "
                                  "provider")


def _normalize_issuer(issuer):
    if issuer and '://' not in issuer:
        # Google historically returned "accounts.google.com" without a
        # scheme.  See OpenID Connect Core, section 2.
        issuer = 'https://' + issuer
    return (issuer or '').rstrip('/')


class Authenticator(object):
    """Handle the OpenID Connect authorization code flow."""

    STATE_SKEY = 'trac_oidc.oauth_state'
    NONCE_SKEY = 'trac_oidc.oauth_nonce'

    def __init__(self, redirect_uri, client_id, client_secret=None,
                 issuer=None, authorization_endpoint=None,
                 token_endpoint=None, userinfo_endpoint=None,
                 scope=DEFAULT_SCOPE, openid_realm=None,
                 token_auth_method='client_secret_post', timeout=10, log=None):
        if not client_id:
            raise TracError("OIDC client_id is not configured")
        if not issuer and not (authorization_endpoint and token_endpoint):
            raise TracError(
                "Either an OIDC issuer or both the authorization and token "
                "endpoints must be configured")
        if token_auth_method not in ('client_secret_post',
                                     'client_secret_basic',
                                     'none'):
            raise TracError(
                "Invalid token_auth_method %r (expected client_secret_post, "
                "client_secret_basic or none)" % token_auth_method)

        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret
        self.issuer = issuer.rstrip('/') if issuer else None
        self.scope = scope
        self.openid_realm = openid_realm
        self.token_auth_method = token_auth_method
        self.timeout = timeout
        self.log = log or logging.getLogger(__name__)

        self._authorization_endpoint = authorization_endpoint
        self._token_endpoint = token_endpoint
        self._userinfo_endpoint = userinfo_endpoint
        self._discovery = None

    # -- endpoints -----------------------------------------------------

    def _discover(self):
        if self._discovery is None:
            if not self.issuer:
                raise AuthenticationError(
                    "No OIDC issuer configured; cannot discover endpoints")
            self._discovery = discover(self.issuer, timeout=self.timeout)
        return self._discovery

    @property
    def authorization_endpoint(self):
        if self._authorization_endpoint:
            return self._authorization_endpoint
        return self._discover()['authorization_endpoint']

    @property
    def token_endpoint(self):
        if self._token_endpoint:
            return self._token_endpoint
        return self._discover()['token_endpoint']

    @property
    def userinfo_endpoint(self):
        if self._userinfo_endpoint:
            return self._userinfo_endpoint
        if self._discovery is not None or self.issuer:
            return self._discover().get('userinfo_endpoint')
        return None

    # -- login flow ----------------------------------------------------

    def get_auth_url(self, req):
        """Return the provider authorization URL and remember state/nonce."""
        state = hex_entropy()
        nonce = hex_entropy()
        req.session[self.STATE_SKEY] = state
        req.session[self.NONCE_SKEY] = nonce

        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': self.scope,
            'state': state,
            'nonce': nonce,
        }
        if self.openid_realm:
            # Google-only extension which causes openid_id (the old
            # OpenID 2.0 identity URL) to be included in the id_token.
            # This is used to migrate users from TracAuthOpenId.
            params['openid.realm'] = self.openid_realm

        endpoint = self.authorization_endpoint
        separator = '&' if '?' in endpoint else '?'
        return endpoint + separator + urlencode(params)

    def get_identity(self, req):
        """Get identity after redirect from the provider.

        This exchanges the returned *code* for credentials, including
        the *id_token*.

        The *id_token* is returned as a mapping (read-only dict-like)
        object.  It contains (among possible others) the following keys:

          - ``iss``, ``sub``: The oidc issuer and subject identifiers
          - ``preferred_username`` (optional)
          - ``name`` (optional)
          - ``email`` (optional)
          - ``openid_id`` (optional)

        If the provider did not include profile claims in the id_token,
        the *userinfo* endpoint is queried lazily when a missing claim
        is accessed.
        """
        code = self._get_code(req)
        nonce = req.session.pop(self.NONCE_SKEY, None)
        credentials = self._get_credentials(code)

        raw_id_token = credentials.get('id_token')
        if not raw_id_token:
            raise AuthenticationError(
                "No id_token returned by OpenID Provider")

        claims = decode_id_token(raw_id_token)
        self._validate_claims(claims)

        if nonce and claims.get('nonce') != nonce:
            raise AuthenticationError("incorrect 'nonce' in id_token")

        deferred_profile = partial(
            self._get_userinfo, credentials.get('access_token'),
            claims.get('sub'))
        return DeferredMapping(claims, deferred_profile)

    def _get_code(self, req):
        """ Extract ``code`` from redirect
        """
        args = req.args
        error = args.getfirst('error')
        error_description = args.getfirst('error_description')
        state = args.getfirst('state', '')
        code = args.getfirst('code')
        expected_state = req.session.pop(self.STATE_SKEY, None)

        if error is not None:
            if error_description:
                raise AuthenticationFailed(
                    "%s: %s" % (error, error_description))
            raise AuthenticationFailed(error)
        elif not expected_state or strings_differ(state, expected_state):
            raise AuthenticationError("incorrect 'state' in redirect")
        elif not code:
            raise AuthenticationError("no 'code' returned in redirect")
        return code

    def _get_credentials(self, code):
        """ Exchange code for credentials
        """
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
        }
        headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': USER_AGENT,
        }

        if self.token_auth_method == 'client_secret_basic':
            if self.client_secret:
                userpass = '%s:%s' % (quote(self.client_id, safe=''),
                                      quote(self.client_secret, safe=''))
                headers['Authorization'] = 'Basic ' + base64.b64encode(
                    userpass.encode('utf-8')).decode('ascii')
        elif self.token_auth_method == 'client_secret_post':
            if self.client_secret:
                data['client_secret'] = self.client_secret

        try:
            response = _json_response(
                self.token_endpoint, data=urlencode(data).encode('ascii'),
                headers=headers, timeout=self.timeout)
        except AuthenticationError:
            raise
        except Exception as ex:  # pragma: NO COVER - defensive
            raise AuthenticationError(
                "Failed to retrieve credentials: %s" % ex)

        if response.get('error'):
            description = response.get('error_description')
            raise AuthenticationError(
                "Failed to retrieve credentials: %s%s"
                % (response['error'],
                   ': ' + description if description else ''))
        return response

    def _validate_claims(self, claims):
        """Validate the security-relevant claims in an id_token."""
        now = time.time()
        try:
            expires = float(claims.get('exp'))
        except (TypeError, ValueError):
            expires = None
        if expires is not None and now > expires + 60:
            raise AuthenticationError("id_token has expired")

        if self.issuer:
            expected = _normalize_issuer(self.issuer)
            actual = _normalize_issuer(claims.get('iss'))
            if actual != expected:
                raise AuthenticationError(
                    "id_token was issued by %r, expected %r"
                    % (claims.get('iss'), self.issuer))

        audience = claims.get('aud')
        if audience is None:
            raise AuthenticationError("id_token has no 'aud' claim")
        if not isinstance(audience, (list, tuple)):
            audience = [audience]
        if self.client_id not in audience:
            raise AuthenticationError(
                "id_token is not intended for this client")

    def _get_userinfo(self, access_token, subject=None):
        """Get profile claims from the OIDC userinfo endpoint."""
        if not access_token:
            return {}

        headers = {
            'Accept': 'application/json',
            'Authorization': 'Bearer %s' % access_token,
            'User-Agent': USER_AGENT,
        }
        try:
            endpoint = self.userinfo_endpoint
            if not endpoint:
                return {}
            profile = _json_response(endpoint, headers=headers,
                                     timeout=self.timeout)
        except AuthenticationError as ex:
            self.log.warning("Failed to retrieve userinfo: %s", ex)
            return {}

        if not isinstance(profile, dict):
            self.log.warning("userinfo response is not a JSON object")
            return {}
        if profile.get('sub') and subject and profile['sub'] != subject:
            self.log.warning(
                "userinfo 'sub' does not match id_token 'sub'; ignoring "
                "userinfo response")
            return {}
        return profile
