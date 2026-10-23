# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Geoffrey T. Dairiki
#
import os

from setuptools import setup

VERSION = '0.2.4.dev0'

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.rst'), encoding='utf-8') as fp:
    README = fp.read()

requires = [
    'trac',
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
    url='https://github.com/haiku/trac-oidc',

    packages=['trac_oidc'],
    include_package_data=True,
    package_data={'trac_oidc': ['templates/*.html']},
    zip_safe=False,

    install_requires=requires,
    python_requires='>=3.6',
    entry_points={
        'trac.plugins': [
            'trac_oidc = trac_oidc.trac_oidc',
            ],
        },

    extras_require={'testing': tests_require},
    )
