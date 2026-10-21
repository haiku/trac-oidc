# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
import os

from setuptools import setup

VERSION = '0.1.5.post1.dev0'

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.rst'), encoding='utf-8') as fp:
    README = fp.read()

requires = [
    'trac',
    'genshi',
    'oauth2client',
    ]

tests_require = [
    'pytest',
    'beautifulsoup4',
    'WebTest',
    ]


setup(
    name='trac-oidc',
    version=VERSION,
    description='OpenID Connect authentication for Trac',
    long_description=README,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Environment :: Web Environment",
        "Framework :: Trac",
        "Intended Audience :: System Administrators",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        ],
    license='Trac license (BSD-like)',
    author='Jeff Dairiki',
    author_email='dairiki@dairiki.org',
    url='https://github.com/trac-hacks/trac-oidc',

    packages=['trac_oidc'],
    include_package_data=True,
    zip_safe=True,

    install_requires=requires,
    python_requires='>=3.6',
    entry_points={
        'trac.plugins': [
            'trac_oidc = trac_oidc.trac_oidc',
            ],
        },

    extras_require={'testing': tests_require},
    )
