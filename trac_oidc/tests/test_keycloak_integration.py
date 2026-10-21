# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
"""End-to-end test of the OIDC flow against a fake Keycloak server.

This exercises the real HTTP code paths (discovery, token exchange and
userinfo) using the same request/response shapes that Keycloak emits.
"""
from __future__ import absolute_import

import base64
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging
import threading
import time
from unittest import mock
from urllib.parse import parse_qs, parse_qsl, urlsplit

import pytest
from trac.test import EnvironmentStub


def _b64encode(value):
    data = json.dumps(value).encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _make_id_token(claims):
    return '%s.%s.%s' % (_b64encode({'alg': 'none'}),
                         _b64encode(claims), 'signature')


class FakeKeycloakHandler(BaseHTTPRequestHandler):
    client_id = 'trac'
    client_secret = 'SEKRET'

    def log_message(self, format, *args):
        pass

    @property
    def issuer(self):
        return 'http://127.0.0.1:%d/realms/trac' % self.server.server_port

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/realms/trac/.well-known/openid-configuration':
            self._send_json({
                'issuer': self.issuer,
                'authorization_endpoint': self.issuer + '/protocol/openid-connect/auth',
                'token_endpoint': self.issuer + '/protocol/openid-connect/token',
                'userinfo_endpoint': self.issuer + '/protocol/openid-connect/userinfo',
                })
        elif self.path == '/realms/trac/protocol/openid-connect/userinfo':
            if self.headers.get('Authorization') != 'Bearer ACCESS':
                self._send_json({'error': 'invalid_token'}, status=401)
                return
            self._send_json({
                'sub': '42',
                'preferred_username': 'jdoe',
                'email': 'jdoe@example.org',
                'name': 'Joe Doe',
                })
        else:
            self._send_json({'error': 'not_found'}, status=404)

    def do_POST(self):
        if self.path != '/realms/trac/protocol/openid-connect/token':
            self._send_json({'error': 'not_found'}, status=404)
            return

        length = int(self.headers.get('Content-Length', 0))
        form = parse_qs(self.rfile.read(length).decode('ascii'))
        if form.get('grant_type') != ['authorization_code'] \
                or form.get('code') != ['CODE'] \
                or form.get('client_id') != [self.client_id] \
                or form.get('client_secret') != [self.client_secret]:
            self._send_json({
                'error': 'invalid_grant',
                'error_description': 'bad code or client',
                }, status=400)
            return

        id_token = _make_id_token({
            'iss': self.issuer,
            'aud': self.client_id,
            'sub': '42',
            'exp': time.time() + 300,
            'nonce': self.server.expected_nonce,
            })
        self._send_json({
            'access_token': 'ACCESS',
            'token_type': 'Bearer',
            'id_token': id_token,
            })

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()


@pytest.fixture
def keycloak_server():
    server = HTTPServer(('127.0.0.1', 0), FakeKeycloakHandler)
    server.expected_nonce = None
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class _RequestArgs(dict):
    getfirst = dict.get


class DummyRequest(object):
    def __init__(self, query=None):
        self.args = _RequestArgs(query or {})
        self.session = {}


def test_keycloak_login_flow(keycloak_server):
    from ..authenticator import Authenticator

    issuer = 'http://127.0.0.1:%d/realms/trac' % keycloak_server.server_port
    auth = Authenticator(
        'https://trac.example.org/trac_oidc/redirect', 'trac',
        client_secret='SEKRET', issuer=issuer,
        log=logging.getLogger('Trac'))

    # Start login: this fetches the discovery document.
    req = DummyRequest()
    auth_url = auth.get_auth_url(req)
    assert auth_url.startswith(issuer + '/protocol/openid-connect/auth?')
    query = dict(parse_qsl(urlsplit(auth_url).query))
    assert query['client_id'] == 'trac'
    assert query['scope'] == 'openid email profile'
    assert query['response_type'] == 'code'
    keycloak_server.expected_nonce = query['nonce']

    # Simulate the provider redirecting back with an authorization code.
    callback = DummyRequest(query={'code': 'CODE', 'state': query['state']})
    callback.session = dict(req.session)
    id_token = auth.get_identity(callback)

    # The id_token has no profile claims, so these come from userinfo.
    assert id_token['sub'] == '42'
    assert id_token['preferred_username'] == 'jdoe'
    assert id_token['email'] == 'jdoe@example.org'
    assert id_token['name'] == 'Joe Doe'


def test_plugin_configures_keycloak(keycloak_server):
    """The trac.ini configuration is wired through to the flow."""
    from ..trac_oidc import OidcPlugin

    issuer = 'http://127.0.0.1:%d/realms/trac' % keycloak_server.server_port
    env = EnvironmentStub(enable=['trac_oidc.*'])
    plugin = OidcPlugin(env)
    plugin.config.set('trac_oidc', 'issuer', issuer)
    plugin.config.set('trac_oidc', 'client_id', 'trac')
    plugin.config.set('trac_oidc', 'client_secret', 'SEKRET')
    plugin.config.set('trac_oidc', 'client_secret_file', '/nonexistent.json')
    plugin.config.set('trac_oidc', 'login_button_text',
                      'Login using Keycloak')

    req = mock.Mock()
    req.session = {}
    req.args = _RequestArgs()
    req.abs_href.trac_oidc.return_value = \
        'https://trac.example.org/trac_oidc/redirect'

    auth = plugin._get_authenticator(req)
    auth_url = auth.get_auth_url(req)
    query = dict(parse_qsl(urlsplit(auth_url).query))
    assert query['client_id'] == 'trac'
    keycloak_server.expected_nonce = query['nonce']

    callback = mock.Mock()
    callback.session = dict(req.session)
    callback.args = _RequestArgs({'code': 'CODE', 'state': query['state']})
    id_token = auth.get_identity(callback)
    assert id_token['preferred_username'] == 'jdoe'
