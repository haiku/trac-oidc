# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
""" Functional tests
"""
from __future__ import absolute_import

from functools import partial
from io import StringIO
from itertools import count
import json
import logging
import os
import re
from shutil import rmtree
import sys
from tempfile import mkdtemp
from unittest import mock
from urllib.parse import parse_qsl, urlencode, urlsplit

import pytest
from trac.admin.console import TracAdmin
from trac.env import open_environment
from trac.perm import PermissionSystem
from trac.web.main import dispatch_request
from trac.web.session import DetachedSession
from webtest import TestApp

from ..authenticator import Authenticator


@pytest.fixture
def get_identity(monkeypatch):
    get_identity = mock.Mock(name='Authenticator.get_identity')
    monkeypatch.setattr(Authenticator, 'get_identity', get_identity)
    return get_identity


_counter = count(1)


@pytest.fixture
def id_token(get_identity):
    id_token = {
        'iss': 'https://example.net',
        'sub': 'sub%d' % next(_counter),
        }
    get_identity.return_value = id_token
    return id_token


def trac_admin(env_path, *commands):
    admin = TracAdmin(env_path)
    logging.disable(logging.CRITICAL)
    save_stdout, sys.stdout = sys.stdout, StringIO()
    try:
        for command in commands:
            admin.onecmd(command)
    finally:
        sys.stdout = save_stdout
        logging.disable(logging.NOTSET)


@pytest.fixture(scope='module')
def env_path(request):
    env_path = mkdtemp(suffix='.env')
    request.addfinalizer(partial(rmtree, env_path))
    trac_admin(env_path, 'initenv testenv sqlite:db/trac.db')

    # Create dummy client_secret.json
    web_secrets = {
        'auth_uri': "https://accounts.example.com/auth",
        'token_uri': "https://accounts.example.com/token",
        'client_id': "ID",
        'client_secret': "SEKRET",
        'redirect_uris': [],
        }
    client_secret_file = os.path.join(env_path, 'conf/client_secret.json')
    with open(client_secret_file, 'w') as fp:
        fp.write(json.dumps({'web': web_secrets}))

    return env_path


@pytest.fixture
def env(env_path):
    return open_environment(env_path, use_cache=True)


TRAC_CONFIGS = [
    {
        'logging': {
            'log_level': 'INFO',
            },
        'components': {
            'trac_oidc.*': 'enabled',
            'trac.web.auth.loginmodule': 'enabled',
            },
        },
    {
        'logging': {
            'log_level': 'INFO',
            },
        'components': {
            'trac_oidc.*': 'enabled',
            'trac.web.auth.loginmodule': 'disabled',
            },
        },
    ]


@pytest.fixture(params=TRAC_CONFIGS)
def test_app(env, request):
    settings = request.param
    for section in settings:
        for name, value in settings[section].items():
            env.config.set(section, name, value)
    env.config.save()

    environ = {
        'trac.env_path': env.path,
        'HTTP_HOST': 'localhost',
        }
    return TestApp(dispatch_request, extra_environ=environ)


def is_logged_in(resp):
    # trac < 1.0.2 uses logout link
    logout_link = resp.html.find('a', href=re.compile(r'/logout(\Z|\?)'))
    if logout_link:
        assert 'Logout' in logout_link
        return True
    # trac >= 1.0.2 uses logout form
    logout_form = resp.forms.get('logout')
    if logout_form:
        assert logout_form.action.endswith('/logout')
        return True
    return False


def check_metanav(resp):
    """Sanity checks on the metanav bar

    This makes sure that we're not getting "logged in as" and "Logout"
    metanav items from both the stock LoginModule and AuthCookieManager.

    """
    metanav = resp.html.find(id='metanav')
    if is_logged_in(resp):
        logged_ins = metanav.find_all(text=re.compile(r'logged in', re.I))
        assert len(logged_ins) == 1
        logouts = metanav.find_all(text=re.compile(r'log\s*out', re.I))
        assert len(logouts) == 1


def oauth_redirect_url(auth_url):
    """ Simulate Oauth2 authentication.
    """
    params = dict(parse_qsl(urlsplit(auth_url).query))
    assert params['response_type'] == 'code'
    assert 'email' in params['scope']
    state = params['state']
    redirect_uri = params['redirect_uri']
    redirect_uri += '?' + urlencode({'state': state, 'code': 'CODE'})
    return redirect_uri


@pytest.fixture
def link_existing_accounts(env):
    def set_mode(mode):
        env.config.set('trac_oidc', 'link_existing_accounts', mode)
        env.config.save()
    yield set_mode
    env.config.set('trac_oidc', 'link_existing_accounts', 'no')
    env.config.save()


def test(test_app, id_token):
    id_token.update({
        'email': 'joe-%s@example.org' % id_token['sub'],
        'name': 'Joe Bloe',
        })

    resp = test_app.get('/prefs')
    check_metanav(resp)
    assert not is_logged_in(resp)

    # Initial login
    resp = resp.click('^Login .* OpenID Connect$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    assert resp.status == '302 Found'
    auth_url = resp.location

    resp = test_app.get(oauth_redirect_url(auth_url))
    assert resp.status == '302 Found'

    resp = resp.follow()
    check_metanav(resp)
    assert is_logged_in(resp)

    # Check that session was created
    prefs = resp.forms['userprefs']
    assert prefs['name'].value == 'Joe Bloe'

    # Update name
    prefs['name'] = 'Joseph Blow'
    resp = prefs.submit()
    resp = resp.maybe_follow()
    prefs = resp.forms['userprefs']
    assert prefs['name'].value == 'Joseph Blow'

    # Logout
    if 'logout' in resp.forms:
        resp = resp.forms['logout'].submit()
    else:
        # trac < 1.0.2 uses link for logout
        resp = resp.click('Logout')
    resp = resp.follow()
    assert not is_logged_in(resp)

    # Log in again
    resp = resp.click('^Login .* OpenID Connect$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    assert resp.status == '302 Found'
    auth_url = resp.location
    resp = test_app.get(oauth_redirect_url(auth_url))
    resp = resp.follow()
    assert is_logged_in(resp)

    # Check that we got the same session
    resp = test_app.get('/prefs')
    prefs = resp.forms['userprefs']
    assert prefs['name'].value == 'Joseph Blow'


def get_accounts_for_subject(env, subject):
    """Return the names of the accounts associated with an OIDC subject.
    """
    rows = env.db_query(
        "SELECT sid FROM session_attribute"
        " WHERE authenticated=1 AND name='trac_oidc.subject' AND value=%s",
        (subject,))
    return [row[0] for row in rows]


def test_link_existing_account(test_app, env, id_token,
                               link_existing_accounts):
    # Simulate an account which was created by the AccountManagerPlugin
    # (or by any other means) before the user logged in via OIDC.
    username = 'joe-%s' % id_token['sub']
    ds = DetachedSession(env, username)
    ds['name'] = 'Joe Bloe'
    ds['email'] = 'joe@example.org'
    ds.save()

    id_token.update({
        'preferred_username': username,
        'email': 'joe@example.org',
        'name': 'Joe Bloe',
        })

    link_existing_accounts('name')

    resp = test_app.get('/prefs')
    resp = resp.click('^Login .* OpenID Connect$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    resp = test_app.get(oauth_redirect_url(resp.location))
    resp = resp.follow()
    assert is_logged_in(resp)
    # The existing account is used, rather than a new one.
    subject = 'https://example.net?sub=%s' % id_token['sub']
    assert get_accounts_for_subject(env, subject) == [username]
    # The attributes of the existing account are preserved.
    ds = DetachedSession(env, username)
    assert ds['name'] == 'Joe Bloe'
    assert ds['email'] == 'joe@example.org'


def test_link_existing_account_email_mismatch(test_app, env, id_token,
                                              link_existing_accounts):
    # An existing account whose email address disagrees with the
    # identity's address must not be linked to, and must not result in a
    # duplicate account being created behind the user's back.
    username = 'joe-%s' % id_token['sub']
    ds = DetachedSession(env, username)
    ds['name'] = 'Joe Bloe'
    ds['email'] = 'joe@example.org'
    ds.save()

    id_token.update({
        'preferred_username': username,
        'email': 'other@example.org',
        'email_verified': True,
        'name': 'Joe Bloe',
        })

    link_existing_accounts('email')

    resp = test_app.get('/prefs')
    resp = resp.click('^Login .* OpenID Connect$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    resp = test_app.get(oauth_redirect_url(resp.location), expect_errors=True)
    assert resp.status_int == 500
    assert 'misaligned email address' in resp.text
    assert 'contact an administrator' in resp.text
    # No account was associated with the identity, and no duplicate
    # account was created.
    subject = 'https://example.net?sub=%s' % id_token['sub']
    assert get_accounts_for_subject(env, subject) == []


def test_linked_account_email_updated(test_app, env, id_token,
                                      link_existing_accounts):
    # An identity which is already associated with a Trac account is
    # trusted to supply the current email address.  If it was changed in
    # Trac after the account was linked, it is updated on login.
    username = 'alex-%s' % id_token['sub']
    subject = 'https://example.net?sub=%s' % id_token['sub']
    ds = DetachedSession(env, username)
    ds['name'] = 'Alex'
    ds['email'] = 'kallisti5@unixzen.com'
    ds['trac_oidc.subject'] = subject
    ds.save()

    id_token.update({
        'preferred_username': username,
        'email': 'alex@terarocket.io',
        'email_verified': True,
        'name': 'Alex',
        })

    link_existing_accounts('email')

    resp = test_app.get('/prefs')
    resp = resp.click('^Login .* OpenID Connect$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    resp = test_app.get(oauth_redirect_url(resp.location))
    resp = resp.follow()
    assert is_logged_in(resp)
    # The association is retained and the Trac email address now matches
    # the one supplied by the identity provider.
    ds = DetachedSession(env, username)
    assert ds['trac_oidc.subject'] == subject
    assert ds['email'] == 'alex@terarocket.io'


def test_no_linking_refuses_duplicate_account(test_app, env, id_token,
                                              link_existing_accounts):
    # Without the link_existing_accounts option, an account with a
    # matching name must not silently be duplicated as "user (2)".
    username = 'joe-%s' % id_token['sub']
    ds = DetachedSession(env, username)
    ds['name'] = 'Joe Bloe'
    ds['email'] = 'joe@example.org'
    ds.save()

    id_token.update({
        'preferred_username': username,
        'email': 'joe@example.org',
        'name': 'Joe Bloe',
        })

    link_existing_accounts('no')

    resp = test_app.get('/prefs')
    resp = resp.click('^Login .* OpenID Connect$', extra_environ={
        'HTTP_REFERER': resp.request.url,
        })
    resp = test_app.get(oauth_redirect_url(resp.location), expect_errors=True)
    assert resp.status_int == 500
    assert 'already exists in Trac' in resp.text
    assert 'contact an administrator' in resp.text
    # No duplicate account was created, and the pre-existing account is
    # left alone.
    subject = 'https://example.net?sub=%s' % id_token['sub']
    assert get_accounts_for_subject(env, subject) == []
    ds = DetachedSession(env, username)
    assert ds.get('trac_oidc.subject') is None


def test_admin_align_email(test_app, env):
    permissions = PermissionSystem(env)
    username = 'admin-email-test'
    permissions.grant_permission('anonymous', 'TRAC_ADMIN')
    try:
        ds = DetachedSession(env, username)
        ds['name'] = 'Admin Email Test'
        ds['email'] = 'old@example.org'
        ds.save()

        resp = test_app.get('/admin/trac_oidc/email')
        assert resp.status_int == 200
        assert 'Align User Email Addresses' in resp.text
        assert ('Ensure the user you are fixing owns both email accounts '
                'to avoid account takeovers!') in resp.text

        form = resp.forms['modoidcemail']
        assert form['username'].value == ''
        assert form['email'].value == ''
        form['username'] = username
        form['email'] = 'new@example.org'
        resp = form.submit().follow()
        assert resp.status_int == 200
        assert "Email address for '%s' updated to 'new@example.org'" \
            % username in resp.text
        assert DetachedSession(env, username)['email'] == 'new@example.org'
    finally:
        permissions.revoke_permission('anonymous', 'TRAC_ADMIN')


def test_admin_unlink_sso_identity(test_app, env, id_token,
                                   link_existing_accounts):
    permissions = PermissionSystem(env)
    username = 'admin-unlink-test'
    subject = 'https://example.net?sub=%s' % id_token['sub']
    permissions.grant_permission('anonymous', 'TRAC_ADMIN')
    try:
        ds = DetachedSession(env, username)
        ds['name'] = 'Admin Unlink Test'
        ds['email'] = 'user@example.org'
        ds['trac_oidc.subject'] = subject
        ds['openid_session_identity_url_data'] = 'https://example.org/old'
        ds.save()

        id_token.update({
            'preferred_username': username,
            'email': 'user@example.org',
            'email_verified': True,
            'name': 'Admin Unlink Test',
            })
        link_existing_accounts('email')

        resp = test_app.get('/admin/trac_oidc/unlink')
        assert resp.status_int == 200
        assert 'Unlink SSO Identity' in resp.text

        form = resp.forms['modoidcunlink']
        assert form['username'].value == ''
        form['username'] = username
        resp = form.submit().follow()
        assert resp.status_int == 200
        assert "SSO identity unlinked from '%s'" % username in resp.text

        ds = DetachedSession(env, username)
        assert 'trac_oidc.subject' not in ds
        # The legacy identity URL is retained.
        assert ds['openid_session_identity_url_data'] == \
            'https://example.org/old'

        # The next login links the identity again automatically.
        resp = test_app.get('/prefs')
        resp = resp.click('^Login .* OpenID Connect$', extra_environ={
            'HTTP_REFERER': resp.request.url,
            })
        resp = test_app.get(oauth_redirect_url(resp.location))
        resp = resp.follow()
        assert is_logged_in(resp)
        assert DetachedSession(env, username)['trac_oidc.subject'] == subject
    finally:
        permissions.revoke_permission('anonymous', 'TRAC_ADMIN')
