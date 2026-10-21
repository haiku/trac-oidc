# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""
"""
from __future__ import absolute_import

import base64
from io import BytesIO
import json
import logging
import time
from unittest import mock
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, parse_qsl, urlsplit, urlunsplit

import pytest
from trac.core import TracError


ISSUER = 'https://keycloak.example.com/realms/trac'


@pytest.fixture(autouse=True)
def clear_discovery_cache():
    from ..authenticator import clear_discovery_cache
    clear_discovery_cache()
    yield
    clear_discovery_cache()


@pytest.fixture
def redirect_url():
    return 'http://localhost/trac_oidc/redirect'


@pytest.fixture
def log():
    return logging.getLogger('Trac')


@pytest.fixture
def authenticator(redirect_url, log):
    from ..authenticator import Authenticator
    return Authenticator(
        redirect_url, 'CLIENT',
        client_secret='SEKRET',
        issuer=ISSUER,
        authorization_endpoint='https://keycloak.example.com/auth',
        token_endpoint='https://keycloak.example.com/token',
        userinfo_endpoint='https://keycloak.example.com/userinfo',
        log=log)


def make_id_token(claims):
    """Build an unsigned JWT with the given claims."""
    def encode(value):
        data = json.dumps(value).encode('utf-8')
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')
    return '%s.%s.%s' % (encode({'alg': 'none'}), encode(claims), 'signature')


def valid_claims(**kwargs):
    claims = {
        'iss': ISSUER,
        'aud': 'CLIENT',
        'sub': '42',
        'exp': time.time() + 300,
        }
    claims.update(kwargs)
    return claims


class _RequestArgs(dict):
    getfirst = dict.get


class DummyRequest(object):
    def __init__(self, query=None):
        self.args = _RequestArgs(query or {})
        self.session = {}


class TestAuthenticatorInit(object):
    def test_requires_client_id(self, redirect_url):
        from ..authenticator import Authenticator
        with pytest.raises(TracError):
            Authenticator(redirect_url, '')

    def test_requires_issuer_or_endpoints(self, redirect_url):
        from ..authenticator import Authenticator
        with pytest.raises(TracError):
            Authenticator(redirect_url, 'CLIENT')

    def test_rejects_invalid_token_auth_method(self, redirect_url):
        from ..authenticator import Authenticator
        with pytest.raises(TracError):
            Authenticator(
                redirect_url, 'CLIENT',
                issuer=ISSUER,
                token_auth_method='magic')


class TestAuthenticator(object):
    def test_get_auth_url(self, authenticator):
        req = DummyRequest()
        auth_url = authenticator.get_auth_url(req)
        split = urlsplit(auth_url)
        assert urlunsplit((split.scheme, split.netloc, split.path, '', '')) \
            == 'https://keycloak.example.com/auth'
        query = dict(parse_qsl(split.query))
        assert query['response_type'] == 'code'
        assert query['client_id'] == 'CLIENT'
        assert query['redirect_uri'] == authenticator.redirect_uri
        assert query['scope'] == 'openid email profile'
        assert query['state']
        assert query['nonce']
        assert req.session[authenticator.STATE_SKEY] == query['state']
        assert req.session[authenticator.NONCE_SKEY] == query['nonce']
        assert 'openid.realm' not in query

    def test_get_auth_url_with_existing_query(self, authenticator):
        authenticator._authorization_endpoint = \
            'https://keycloak.example.com/auth?foo=bar'
        auth_url = authenticator.get_auth_url(DummyRequest())
        assert auth_url.startswith(
            'https://keycloak.example.com/auth?foo=bar&')

    def test_get_auth_url_with_openid_realm(self, authenticator):
        authenticator.openid_realm = 'https://example.org/'
        auth_url = authenticator.get_auth_url(DummyRequest())
        query = dict(parse_qsl(urlsplit(auth_url).query))
        assert query['openid.realm'] == 'https://example.org/'

    def test_get_identity(self, authenticator):
        claims = valid_claims(nonce='NONCE', preferred_username='joe')
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'})
        req.session[authenticator.STATE_SKEY] = 'STATE'
        req.session[authenticator.NONCE_SKEY] = 'NONCE'
        authenticator._get_credentials = mock.Mock(return_value={
            'id_token': make_id_token(claims),
            'access_token': 'ACCESS',
            })
        authenticator._get_userinfo = mock.Mock(return_value={})

        id_token = authenticator.get_identity(req)
        assert dict(id_token) == claims
        assert authenticator.STATE_SKEY not in req.session
        assert authenticator.NONCE_SKEY not in req.session

    def test_get_identity_fetches_userinfo_lazily(self, authenticator):
        claims = valid_claims(nonce='NONCE')
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'})
        req.session[authenticator.STATE_SKEY] = 'STATE'
        req.session[authenticator.NONCE_SKEY] = 'NONCE'
        authenticator._get_credentials = mock.Mock(return_value={
            'id_token': make_id_token(claims),
            'access_token': 'ACCESS',
            })
        authenticator._get_userinfo = mock.Mock(
            return_value={'preferred_username': 'joe'})

        id_token = authenticator.get_identity(req)
        assert authenticator._get_userinfo.call_count == 0
        assert id_token['preferred_username'] == 'joe'
        assert authenticator._get_userinfo.call_args == mock.call(
            'ACCESS', '42')

    def test_get_identity_without_nonce(self, authenticator):
        claims = valid_claims()
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'})
        req.session[authenticator.STATE_SKEY] = 'STATE'
        authenticator._get_credentials = mock.Mock(return_value={
            'id_token': make_id_token(claims),
            })
        id_token = authenticator.get_identity(req)
        assert id_token['sub'] == '42'

    def test_get_identity_bad_nonce(self, authenticator):
        from ..authenticator import AuthenticationError
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'})
        req.session[authenticator.STATE_SKEY] = 'STATE'
        req.session[authenticator.NONCE_SKEY] = 'EXPECTED'
        authenticator._get_credentials = mock.Mock(return_value={
            'id_token': make_id_token(valid_claims(nonce='WRONG')),
            })
        with pytest.raises(AuthenticationError):
            authenticator.get_identity(req)

    def test_get_identity_no_id_token(self, authenticator):
        from ..authenticator import AuthenticationError
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'})
        req.session[authenticator.STATE_SKEY] = 'STATE'
        authenticator._get_credentials = mock.Mock(return_value={})
        with pytest.raises(AuthenticationError):
            authenticator.get_identity(req)

    def test_get_identity_resets_state(self, authenticator):
        from ..authenticator import AuthenticationError
        req = DummyRequest(query={'code': 'CODE', 'state': 'STATE'})
        req.session[authenticator.STATE_SKEY] = 'STATE'
        authenticator._get_credentials = mock.Mock(return_value={
            'id_token': make_id_token(valid_claims()),
            })
        authenticator.get_identity(req)
        with pytest.raises(AuthenticationError):
            authenticator.get_identity(req)

    def test_get_code(self, authenticator):
        state = 'abcdef'
        req = DummyRequest(query={'code': 'CODE', 'state': state})
        req.session[authenticator.STATE_SKEY] = state
        assert authenticator._get_code(req) == 'CODE'

    def test_get_code_authentication_failure(self, authenticator):
        from ..authenticator import AuthenticationFailed
        req = DummyRequest(query={'error': 'error message'})
        with pytest.raises(AuthenticationFailed) as exc_info:
            authenticator._get_code(req)
        assert 'error message' in exc_info.exconly()

    def test_get_code_authentication_failure_with_description(
            self, authenticator):
        from ..authenticator import AuthenticationFailed
        req = DummyRequest(query={
            'error': 'access_denied',
            'error_description': 'User denied access',
            })
        with pytest.raises(AuthenticationFailed) as exc_info:
            authenticator._get_code(req)
        assert 'access_denied: User denied access' in exc_info.exconly()

    @pytest.mark.parametrize('state, oauth_state', [
        ('wrong', 'somestate'),
        (None, 'somestate'),
        (None, None),
        ('unexpected', None),
        ])
    def test_get_code_incorrect_state(self, authenticator,
                                      state, oauth_state):
        from ..authenticator import AuthenticationError
        req = DummyRequest(query={'state': state} if state else None)
        if oauth_state is not None:
            req.session[authenticator.STATE_SKEY] = oauth_state
        with pytest.raises(AuthenticationError):
            authenticator._get_code(req)

    def test_get_code_missing_code(self, authenticator):
        from ..authenticator import AuthenticationError
        state = 'abcdef'
        req = DummyRequest(query={'state': state})
        req.session[authenticator.STATE_SKEY] = state
        with pytest.raises(AuthenticationError):
            authenticator._get_code(req)

    def test_get_credentials(self, authenticator, monkeypatch):
        from .. import authenticator as module
        response = {'id_token': 'TOKEN', 'access_token': 'ACCESS'}
        json_response = mock.Mock(return_value=response)
        monkeypatch.setattr(module, '_json_response', json_response)

        credentials = authenticator._get_credentials('CODE')
        assert credentials == response
        assert json_response.call_count == 1
        args, kwargs = json_response.call_args
        assert args[0] == 'https://keycloak.example.com/token'
        data = parse_qs(kwargs['data'].decode('ascii'))
        assert data['grant_type'] == ['authorization_code']
        assert data['code'] == ['CODE']
        assert data['client_id'] == ['CLIENT']
        assert data['client_secret'] == ['SEKRET']
        assert kwargs['headers']['Content-Type'] == \
            'application/x-www-form-urlencoded'

    def test_get_credentials_client_secret_basic(self, authenticator,
                                                 monkeypatch):
        from .. import authenticator as module
        authenticator.token_auth_method = 'client_secret_basic'
        json_response = mock.Mock(return_value={})
        monkeypatch.setattr(module, '_json_response', json_response)
        authenticator._get_credentials('CODE')
        headers = json_response.call_args[1]['headers']
        expected = base64.b64encode(b'CLIENT:SEKRET').decode('ascii')
        assert headers['Authorization'] == 'Basic ' + expected

    def test_get_credentials_no_client_auth(self, authenticator,
                                            monkeypatch):
        from .. import authenticator as module
        authenticator.token_auth_method = 'none'
        json_response = mock.Mock(return_value={})
        monkeypatch.setattr(module, '_json_response', json_response)
        authenticator._get_credentials('CODE')
        data = parse_qs(json_response.call_args[1]['data'].decode('ascii'))
        assert 'client_secret' not in data
        assert 'Authorization' not in json_response.call_args[1]['headers']

    def test_get_credentials_error_response(self, authenticator, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_json_response', mock.Mock(
            return_value={'error': 'invalid_grant',
                          'error_description': 'Code expired'}))
        with pytest.raises(AuthenticationError) as exc_info:
            authenticator._get_credentials('CODE')
        assert 'invalid_grant: Code expired' in exc_info.exconly()

    def test_get_credentials_http_failure(self, authenticator, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_json_response', mock.Mock(
            side_effect=AuthenticationError('HTTP 400')))
        with pytest.raises(AuthenticationError):
            authenticator._get_credentials('CODE')

    def test_validate_claims(self, authenticator):
        authenticator._validate_claims(valid_claims())

    def test_validate_claims_expired(self, authenticator):
        from ..authenticator import AuthenticationError
        with pytest.raises(AuthenticationError):
            authenticator._validate_claims(
                valid_claims(exp=time.time() - 3600))

    def test_validate_claims_missing_exp(self, authenticator):
        claims = valid_claims()
        del claims['exp']
        authenticator._validate_claims(claims)

    def test_validate_claims_wrong_issuer(self, authenticator):
        from ..authenticator import AuthenticationError
        with pytest.raises(AuthenticationError):
            authenticator._validate_claims(
                valid_claims(iss='https://evil.example.com'))

    def test_validate_claims_google_issuer_without_scheme(self, redirect_url):
        from ..authenticator import Authenticator
        auth = Authenticator(redirect_url, 'CLIENT',
                             issuer='https://accounts.google.com')
        auth._validate_claims(valid_claims(
            iss='accounts.google.com', aud='CLIENT'))
        auth._validate_claims(valid_claims(
            iss='https://accounts.google.com/', aud='CLIENT'))

    def test_validate_claims_missing_audience(self, authenticator):
        from ..authenticator import AuthenticationError
        claims = valid_claims()
        del claims['aud']
        with pytest.raises(AuthenticationError):
            authenticator._validate_claims(claims)

    def test_validate_claims_wrong_audience(self, authenticator):
        from ..authenticator import AuthenticationError
        with pytest.raises(AuthenticationError):
            authenticator._validate_claims(valid_claims(aud='OTHER'))

    def test_validate_claims_audience_list(self, authenticator):
        authenticator._validate_claims(
            valid_claims(aud=['OTHER', 'CLIENT']))

    def test_get_userinfo(self, authenticator, monkeypatch):
        from .. import authenticator as module
        json_response = mock.Mock(return_value={
            'sub': '42', 'preferred_username': 'joe'})
        monkeypatch.setattr(module, '_json_response', json_response)
        profile = authenticator._get_userinfo('ACCESS', '42')
        assert profile == {'sub': '42', 'preferred_username': 'joe'}
        assert json_response.call_args[1]['headers']['Authorization'] == \
            'Bearer ACCESS'

    def test_get_userinfo_without_endpoint(self, redirect_url):
        from ..authenticator import Authenticator
        auth = Authenticator(
            redirect_url, 'CLIENT',
            authorization_endpoint='https://example.com/auth',
            token_endpoint='https://example.com/token')
        assert auth._get_userinfo('ACCESS', '42') == {}

    def test_get_userinfo_without_access_token(self, authenticator):
        assert authenticator._get_userinfo(None, '42') == {}

    def test_get_userinfo_failure(self, authenticator, monkeypatch, caplog):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_json_response', mock.Mock(
            side_effect=AuthenticationError('HTTP 500')))
        assert authenticator._get_userinfo('ACCESS', '42') == {}
        assert 'Failed to retrieve userinfo' in caplog.text

    def test_get_userinfo_subject_mismatch(self, authenticator, monkeypatch,
                                           caplog):
        from .. import authenticator as module
        monkeypatch.setattr(module, '_json_response', mock.Mock(
            return_value={'sub': 'OTHER'}))
        assert authenticator._get_userinfo('ACCESS', '42') == {}
        assert "userinfo 'sub' does not match" in caplog.text

    def test_get_userinfo_not_an_object(self, authenticator, monkeypatch,
                                        caplog):
        from .. import authenticator as module
        monkeypatch.setattr(module, '_json_response', mock.Mock(
            return_value=['not', 'an', 'object']))
        assert authenticator._get_userinfo('ACCESS', '42') == {}
        assert 'not a JSON object' in caplog.text


class TestDiscovery(object):
    def test_discovers_endpoints(self, redirect_url, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import Authenticator
        document = {
            'issuer': ISSUER,
            'authorization_endpoint': 'https://keycloak.example.com/auth',
            'token_endpoint': 'https://keycloak.example.com/token',
            'userinfo_endpoint': 'https://keycloak.example.com/userinfo',
            }
        json_response = mock.Mock(return_value=document)
        monkeypatch.setattr(module, '_json_response', json_response)

        auth = Authenticator(redirect_url, 'CLIENT', issuer=ISSUER)
        assert auth.authorization_endpoint == document['authorization_endpoint']
        assert auth.token_endpoint == document['token_endpoint']
        assert auth.userinfo_endpoint == document['userinfo_endpoint']
        assert json_response.call_count == 1
        assert json_response.call_args[0][0] == \
            ISSUER + '/.well-known/openid-configuration'

    def test_discovery_is_cached(self, redirect_url, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import Authenticator
        document = {
            'authorization_endpoint': 'https://keycloak.example.com/auth',
            'token_endpoint': 'https://keycloak.example.com/token',
            }
        json_response = mock.Mock(return_value=document)
        monkeypatch.setattr(module, '_json_response', json_response)

        auth1 = Authenticator(redirect_url, 'CLIENT', issuer=ISSUER)
        auth2 = Authenticator(redirect_url, 'CLIENT', issuer=ISSUER)
        assert auth1.authorization_endpoint == auth2.authorization_endpoint
        assert json_response.call_count == 1

    def test_discovery_missing_endpoints(self, redirect_url, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import Authenticator, AuthenticationError
        monkeypatch.setattr(module, '_json_response', mock.Mock(
            return_value={'issuer': ISSUER}))
        auth = Authenticator(redirect_url, 'CLIENT', issuer=ISSUER)
        with pytest.raises(AuthenticationError):
            auth.authorization_endpoint

    def test_discover_without_issuer(self, redirect_url):
        from ..authenticator import Authenticator, AuthenticationError
        auth = Authenticator(
            redirect_url, 'CLIENT',
            authorization_endpoint='https://example.com/auth',
            token_endpoint='https://example.com/token')
        auth._authorization_endpoint = None
        with pytest.raises(AuthenticationError):
            auth.authorization_endpoint


class TestClientSecretsFile(object):
    def test_web_format(self, tmp_path):
        from ..authenticator import client_secrets_from_file
        path = tmp_path / 'client_secret.json'
        path.write_text(json.dumps({'web': {
            'auth_uri': 'https://accounts.example.com/auth',
            'token_uri': 'https://accounts.example.com/token',
            'client_id': 'ID',
            'client_secret': 'SEKRET',
            }}))
        secrets = client_secrets_from_file(str(path))
        assert secrets == {
            'client_id': 'ID',
            'client_secret': 'SEKRET',
            'issuer': None,
            'authorization_endpoint': 'https://accounts.example.com/auth',
            'token_endpoint': 'https://accounts.example.com/token',
            'userinfo_endpoint': None,
            }

    def test_flat_keycloak_format(self, tmp_path):
        from ..authenticator import client_secrets_from_file
        path = tmp_path / 'client_secret.json'
        path.write_text(json.dumps({
            'issuer': ISSUER,
            'authorization_endpoint': 'https://keycloak.example.com/auth',
            'token_endpoint': 'https://keycloak.example.com/token',
            'userinfo_endpoint': 'https://keycloak.example.com/userinfo',
            'client_id': 'ID',
            'client_secret': 'SEKRET',
            }))
        secrets = client_secrets_from_file(str(path))
        assert secrets['issuer'] == ISSUER
        assert secrets['userinfo_endpoint'] == \
            'https://keycloak.example.com/userinfo'

    def test_missing_client_id(self, tmp_path):
        from ..authenticator import client_secrets_from_file
        path = tmp_path / 'client_secret.json'
        path.write_text(json.dumps({'web': {}}))
        with pytest.raises(TracError):
            client_secrets_from_file(str(path))

    def test_missing_file(self, tmp_path):
        from ..authenticator import client_secrets_from_file
        with pytest.raises(TracError):
            client_secrets_from_file(str(tmp_path / 'nope.json'))

    def test_invalid_json(self, tmp_path):
        from ..authenticator import client_secrets_from_file
        path = tmp_path / 'client_secret.json'
        path.write_text('}')
        with pytest.raises(TracError):
            client_secrets_from_file(str(path))


class TestDecodeIdToken(object):
    def test_decode(self):
        from ..authenticator import decode_id_token
        assert decode_id_token(make_id_token({'sub': '42'})) == {'sub': '42'}

    @pytest.mark.parametrize('token', [
        'not-a-jwt',
        'a.b',
        'a.%%%%.c',
        ])
    def test_decode_failure(self, token):
        from ..authenticator import AuthenticationError, decode_id_token
        with pytest.raises(AuthenticationError):
            decode_id_token(token)


class TestHttpRequest(object):
    def test_success(self, monkeypatch):
        from .. import authenticator as module
        response = mock.MagicMock(name='response')
        response.status = 200
        response.read.return_value = b'{"foo": "bar"}'
        response.__enter__.return_value = response
        urlopen = mock.Mock(return_value=response)
        monkeypatch.setattr(module, 'urlopen', urlopen)

        assert module._http_request('https://example.com') == \
            (200, b'{"foo": "bar"}')
        assert urlopen.call_count == 1

    def test_http_error(self, monkeypatch):
        from .. import authenticator as module
        error = HTTPError('https://example.com', 400, 'Bad Request', {},
                          BytesIO(b'error'))
        monkeypatch.setattr(module, 'urlopen', mock.Mock(side_effect=error))
        assert module._http_request('https://example.com') == (400, b'error')

    def test_url_error(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, 'urlopen', mock.Mock(
            side_effect=URLError('no route to host')))
        with pytest.raises(AuthenticationError):
            module._http_request('https://example.com')

    def test_os_error(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, 'urlopen', mock.Mock(
            side_effect=OSError('network down')))
        with pytest.raises(AuthenticationError):
            module._http_request('https://example.com')

    def test_json_response_success(self, monkeypatch):
        from .. import authenticator as module
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(200, b'{"foo": "bar"}')))
        assert module._json_response('https://example.com') == {'foo': 'bar'}

    def test_json_response_invalid_json(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(200, b'not json')))
        with pytest.raises(AuthenticationError):
            module._json_response('https://example.com')

    def test_json_response_http_error(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(500, b'boom')))
        with pytest.raises(AuthenticationError) as exc_info:
            module._json_response('https://example.com')
        assert 'HTTP 500' in exc_info.exconly()

    def test_json_response_undecodable_body(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(200, b'\xff')))
        with pytest.raises(AuthenticationError):
            module._json_response('https://example.com')

    def test_json_response_provider_error(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(400, json.dumps({
                'error': 'invalid_grant',
                'error_description': 'Code expired',
                }).encode('utf-8'))))
        with pytest.raises(AuthenticationError) as exc_info:
            module._json_response('https://example.com')
        assert 'invalid_grant: Code expired' in exc_info.exconly()

    def test_json_response_provider_error_without_description(
            self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(400, b'{"error": "invalid_grant"}')))
        with pytest.raises(AuthenticationError) as exc_info:
            module._json_response('https://example.com')
        assert 'invalid_grant' in exc_info.exconly()

    def test_json_response_http_error_with_json_body(self, monkeypatch):
        from .. import authenticator as module
        from ..authenticator import AuthenticationError
        monkeypatch.setattr(module, '_http_request', mock.Mock(
            return_value=(503, b'{"message": "unavailable"}')))
        with pytest.raises(AuthenticationError) as exc_info:
            module._json_response('https://example.com')
        assert 'HTTP 503' in exc_info.exconly()
