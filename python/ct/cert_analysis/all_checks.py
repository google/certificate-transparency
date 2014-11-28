from ct.cert_analysis import serial_number
from ct.cert_analysis import validity
from ct.cert_analysis import dnsnames
from ct.cert_analysis import ip_addresses
from ct.cert_analysis import algorithm
from ct.cert_analysis import ca_field
from ct.cert_analysis import ocsp_pointers
from ct.cert_analysis import crl_pointers

ALL_CHECKS = [serial_number.CheckNegativeSerialNumber(),
              validity.CheckValidityNotBeforeFuture(),
              validity.CheckValidityCorrupt(),
              dnsnames.CheckValidityOfDnsnames(),
              dnsnames.CheckCorruptSANExtension(),
              ip_addresses.CheckPrivateIpAddresses(),
              ip_addresses.CheckCorruptIpAddresses(),
              algorithm.CheckSignatureAlgorithmsMismatch(),
              algorithm.CheckCertificateAlgorithmSHA1After2017(),
              algorithm.CheckTbsCertificateAlgorithmSHA1Ater2017(),
              ca_field.CheckCATrue(),
              ocsp_pointers.CheckOcspExistence(),
              ocsp_pointers.CheckCorruptOrMultipleAiaExtension(),
              crl_pointers.CheckCrlExistence(),
              crl_pointers.CheckCorruptOrMultipleCrlExtension(),]
