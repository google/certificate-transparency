#!/usr/bin/env python
import pymongo
import time
import unittest

from ct.client.mongo_db import MongoDB
from ct.client.database_test import DatabaseTest

class MongoDBTest(unittest.TestCase, DatabaseTest):
    def setUp(self):
        self.db_name = "test-%d" % time.time()
        self.database = MongoDB(self.db_name)

    def db(self):
        return self.database

    def tearDown(self):
        m = pymongo.MongoClient()
        m.drop_database(self.db_name)        
        
if __name__ == '__main__':
    unittest.main()
