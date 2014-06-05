#include "log/ct_extensions.h"

#include <glog/logging.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include <string.h>

namespace ct {
int NID_ctSignedCertificateTimestampList = 0;
int NID_ctEmbeddedSignedCertificateTimestampList = 0;
int NID_ctPoison = 0;
int NID_ctPrecertificateSigning = 0;

// The SCT list in the extension of a superfluous certificate
const char kSCTListOID[] = "1.3.6.1.4.1.11129.2.4.1";
// The SCT list embedded in the certificate itself
const char kEmbeddedSCTListOID[] = "1.3.6.1.4.1.11129.2.4.2";
// The poison extension
const char kPoisonOID[] = "1.3.6.1.4.1.11129.2.4.3";
// Extended Key Usage value for Precertificate signing
const char kPrecertificateSigningOID[] = "1.3.6.1.4.1.11129.2.4.4";

static const char kSCTListSN[] = "ctSCT";
static const char kSCTListLN[] =
    "X509v3 Certificate Transparency Signed Certificate Timestamp List";

static const char kEmbeddedSCTListSN[] = "ctEmbeddedSCT";
static const char kEmbeddedSCTListLN[] = "X509v3 Certificate Transparency "
    "Embedded Signed Certificate Timestamp List";
static const char kPoisonSN[] = "ctPoison";
static const char kPoisonLN[] = "X509v3 Certificate Transparency Poison";
static const char kPrecertificateSigningSN[] = "ctPresign";
static const char kPrecertificateSigningLN[] = "Certificate Transparency "
    "Precertificate Signing";

static const char kASN1NullValue[] = "NULL";

// String conversion for an ASN1 NULL
static char *ASN1NullToString(X509V3_EXT_METHOD *method, ASN1_NULL *asn1_null) {
  if (asn1_null == NULL)
    return NULL;
  char *buf = strdup(kASN1NullValue);
  return buf;
}

// String conversion from an ASN1:NULL conf.
static ASN1_NULL *StringToASN1Null(X509V3_EXT_METHOD *method, X509V3_CTX *ctx,
                                   char *str) {
  if (str == NULL || strcmp(str, kASN1NullValue) != 0) {
    return NULL;
  }

  return ASN1_NULL_new();
}

static X509V3_EXT_METHOD ct_sctlist_method = {
  0,  // ext_nid, NID, will be created by OBJ_create()
  0,  // flags
  ASN1_ITEM_ref(ASN1_OCTET_STRING), // the object is an octet string
  0, 0, 0, 0,  // ignored since the field above is set
  // Create from, and print to, a hex string
  // Allows to specify the extension configuration like so:
  // ctSCT = <hexstring_value>
  // (Unused - we just plumb the bytes in the fake cert directly.)
  reinterpret_cast<X509V3_EXT_I2S>(i2s_ASN1_OCTET_STRING),
  reinterpret_cast<X509V3_EXT_S2I>(s2i_ASN1_OCTET_STRING),
  0, 0,
  0, 0,
  NULL   // usr_data
};

static X509V3_EXT_METHOD ct_embeddedsctlist_method = {
  0,  // ext_nid, NID, will be created by OBJ_create()
  0,  // flags
  ASN1_ITEM_ref(ASN1_OCTET_STRING), // the object is an octet string
  0, 0, 0, 0,  // ignored since the field above is set
  // Create from, and print to, a hex string
  // Allows to specify the extension configuration like so:
  // ctEmbeddedSCT = <hexstring_value>
  // (Unused, as we're not issuing certs.)
  reinterpret_cast<X509V3_EXT_I2S>(i2s_ASN1_OCTET_STRING),
  reinterpret_cast<X509V3_EXT_S2I>(s2i_ASN1_OCTET_STRING),
  0, 0,
  0, 0,
  NULL   // usr_data
};

static X509V3_EXT_METHOD ct_poison_method = {
  0,  // ext_nid, NID, will be created by OBJ_create()
  0,  // flags
  ASN1_ITEM_ref(ASN1_NULL), // the object is an ASN1 NULL
  0, 0, 0, 0,  // ignored since the above is set
  // Create from, and print to, a hex string
  // Allows to specify the extension configuration like so:
  // ctPoison = "NULL"
  // (Unused, as we're not issuing certs.)
  reinterpret_cast<X509V3_EXT_I2S>(ASN1NullToString),
  reinterpret_cast<X509V3_EXT_S2I>(StringToASN1Null),
  0, 0,
  0, 0,
  NULL   // usr_data
};

void LoadCtExtensions() {
  ct_sctlist_method.ext_nid = OBJ_create(kSCTListOID, kSCTListSN, kSCTListLN);
  CHECK_NE(ct_sctlist_method.ext_nid, 0);
  CHECK_EQ(1, X509V3_EXT_add(&ct_sctlist_method));
  NID_ctSignedCertificateTimestampList = ct_sctlist_method.ext_nid;

  ct_embeddedsctlist_method.ext_nid = OBJ_create(kEmbeddedSCTListOID,
                                                 kEmbeddedSCTListSN,
                                                 kEmbeddedSCTListLN);
  CHECK_NE(ct_embeddedsctlist_method.ext_nid, 0);
  CHECK_EQ(1, X509V3_EXT_add(&ct_embeddedsctlist_method));
  NID_ctEmbeddedSignedCertificateTimestampList =
      ct_embeddedsctlist_method.ext_nid;

  ct_poison_method.ext_nid = OBJ_create(kPoisonOID, kPoisonSN, kPoisonLN);
  CHECK_NE(ct_poison_method.ext_nid, 0);
  CHECK_EQ(1, X509V3_EXT_add(&ct_poison_method));
  NID_ctPoison = ct_poison_method.ext_nid;

  int precert_signing_nid = OBJ_create(kPrecertificateSigningOID,
                                       kPrecertificateSigningSN,
                                       kPrecertificateSigningLN);
  CHECK_NE(precert_signing_nid, 0);
  NID_ctPrecertificateSigning = precert_signing_nid;
}

}  // namespace ct
