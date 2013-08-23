#!/usr/bin/env python

import unittest

from ct.crypto import error
from ct.crypto.asn1 import x509_time


class TimeTest(unittest.TestCase):
    def verify_time(self, time_struct, year, month, day, hour, minute, sec):
        self.assertEqual(year, time_struct.tm_year)
        self.assertEqual(month, time_struct.tm_mon)
        self.assertEqual(day, time_struct.tm_mday)
        self.assertEqual(hour, time_struct.tm_hour)
        self.assertEqual(minute, time_struct.tm_min)
        self.assertEqual(sec, time_struct.tm_sec)

    def test_time(self):
        t = x509_time.UTCTime("130822153902Z").gmtime()
        self.verify_time(t, 2013, 8, 22, 15, 39, 2)

        t = x509_time.GeneralizedTime("20130822153902Z").gmtime()
        self.verify_time(t, 2013, 8, 22, 15, 39, 2)

    def test_utc_time_1900(self):
        t = x509_time.UTCTime("500822153902Z").gmtime()
        self.verify_time(t, 1950, 8, 22, 15, 39, 2)

    def test_time_invalid(self):
        t = x509_time.UTCTime("131322153902Z")
        self.assertRaises(error.ASN1Error, t.gmtime)
        t = x509_time.UTCTime("201301322153902Z")
        self.assertRaises(error.ASN1Error, t.gmtime)

if __name__ == "__main__":
    unittest.main()
