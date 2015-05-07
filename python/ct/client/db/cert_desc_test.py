#!/usr/bin/env python
# coding=utf-8
import time
import unittest
from ct.client.db import cert_desc
from ct.crypto import cert
from ct.cert_analysis import all_checks
from ct.cert_analysis import observation

CERT = cert.Certificate.from_der_file("ct/crypto/testdata/google_cert.der")

class CertificateDescriptionTest(unittest.TestCase):
    def test_from_cert(self):
        observations = []
        for check in all_checks.ALL_CHECKS:
            observations += check.check(CERT) or []
        observations.append(observation.Observation(
            "AE", u'ćę©ß→æ→ćąßę-ß©ąńśþa©ęńć←', (u'əę”ąłęµ', u'…łą↓ð→↓ś→ę')))
        proto = cert_desc.from_cert(CERT, observations)
        self.assertEqual(proto.der, CERT.to_der())

        subject = [(att.type, att.value) for att in proto.subject]
        cert_subject = [(type_.short_name,
                     cert_desc.to_unicode('.'.join(
                             cert_desc.process_name(value.human_readable()))))
                    for type_, value in CERT.subject()]
        self.assertItemsEqual(cert_subject, subject)

        issuer = [(att.type, att.value) for att in proto.issuer]
        cert_issuer = [(type_.short_name,
                     cert_desc.to_unicode('.'.join(
                             cert_desc.process_name(value.human_readable()))))
                    for type_, value in CERT.issuer()]
        self.assertItemsEqual(cert_issuer, issuer)

        subject_alternative_names = [(att.type, att.value)
                                     for att in proto.subject_alternative_names]
        cert_subject_alternative_names = [(san.component_key(),
                                           cert_desc.to_unicode('.'.join(
                                            cert_desc.process_name(
                                     san.component_value().human_readable()))))
                    for san in CERT.subject_alternative_names()]
        self.assertItemsEqual(cert_subject_alternative_names,
                              subject_alternative_names)

        self.assertEqual(proto.version, str(CERT.version().value))
        self.assertEqual(proto.serial_number,
                         str(CERT.serial_number().human_readable()
                             .upper().replace(':', '')))
        self.assertEqual(time.gmtime(proto.validity.not_before / 1000),
                         CERT.not_before())
        self.assertEqual(time.gmtime(proto.validity.not_after / 1000),
                         CERT.not_after())

        observations_tuples = [(unicode(obs.description),
                                unicode(obs.reason) if obs.reason else u'',
                                obs.details_to_proto())
                               for obs in observations]
        proto_obs = [(obs.description, obs.reason, obs.details)
                     for obs in proto.observations]
        self.assertItemsEqual(proto_obs, observations_tuples)

    def test_process_value(self):
        self.assertEqual(['London'], cert_desc.process_name('London'))
        self.assertEqual(['Bob Smith'], cert_desc.process_name('Bob Smith'))
        self.assertEqual(['com', 'googleapis', 'ct'], cert_desc.process_name('ct.googleapis.com'))
        self.assertEqual(['com', 'github'], cert_desc.process_name('gItHuB.CoM'))
        # These two are unfortunate outcomes:
        # 1. single-word hostnames are indistinguishable from single-word CN
        # terms like State, City, Organization
        self.assertEqual(['LOCALhost'], cert_desc.process_name('LOCALhost'))
        # 2. IP addresses should perhaps not be reversed like hostnames are
        self.assertEqual(['1', '0', '168', '192'], cert_desc.process_name('192.168.0.1'))

if __name__ == "__main__":
    unittest.main()
