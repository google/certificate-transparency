#!/usr/bin/env python

import unittest

from ct.client import sqlite_connection as sqlitecon
from ct.client import sqlite_cert_db
from ct.client import cert_db_test

class SQLiteCertDBTest(unittest.TestCase, cert_db_test.CertDBTest):
    def setUp(self):
        self.database = sqlite_cert_db.SQLiteCertDB(
            sqlitecon.SQLiteConnectionManager(":memory:", keepalive=True))
    def db(self):
        return self.database

if __name__ == '__main__':
    unittest.main()
