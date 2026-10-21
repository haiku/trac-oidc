# -*- coding: utf-8 -*-
#
# Copyright (C) 2026 Alexander von Gluck IV
#
"""Test environment setup.

Trac 1.6 (the newest Trac release) is not quite compatible with
Python 3.14: ``trac.db.sqlite_backend`` reads the module-level
``sqlite3.version_info`` attribute, which was removed in Python 3.14.

Trac only uses that attribute to build an informational ``pysqlite``
version string, so a stand-in value is sufficient to let the test suite
run on Python 3.14.
"""
import sqlite3


if not hasattr(sqlite3, 'version_info'):
    # Python 3.14 removed the pysqlite version attributes from the
    # sqlite3 module.  Trac only reports this value, never compares it,
    # so any plausible value will do.
    sqlite3.version_info = (2, 6, 0)
