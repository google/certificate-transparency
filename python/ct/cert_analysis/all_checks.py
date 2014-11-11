from ct.cert_analysis import serial_number
from ct.cert_analysis import validity
from ct.cert_analysis import dnsnames
from ct.cert_analysis import ip_addresses
from ct.cert_analysis import algorithm
from ct.cert_analysis import ca_field

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
              ca_field.CheckCATrue(),]
