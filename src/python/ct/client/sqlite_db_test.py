#!/usr/bin/env python

import unittest

from  ct.client import sqlite_db, database_test

class SQLiteDBTest(unittest.TestCase, database_test.DatabaseTest):
    def setUp(self):
        self.database = sqlite_db.SQLiteDB(":memory:", keepalive=True)
    def db(self):
        return self.database

if __name__ == '__main__':
    unittest.main()
