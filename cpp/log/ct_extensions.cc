#include "log/ct_extensions.h"

#include <glog/logging.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include <string.h>

namespace cert_trans {

int NID_ctPrecertificateRedactedLabelCount = 0;
int NID_ctNameConstraintNologIntermediateCa = 0;
int NID_ctV2CmsPayloadContentType = 0;

// Extension indicating consent that certs from an intermediate CA with name
// constraints may not be logged (not used in V1)
const char kNameConstraintNologIntermediateOID[] = "1.3.6.1.4.1.11129.2.4.7";
// Extension for wildcard redacted Precertificate indicating redaction count
// (not used in V1)
const char kPrecertificateRedactedLabelOID[] = "1.3.6.1.4.1.11129.2.4.6";
// V2 Precert content type
// TODO: Required content type not defined in draft yet. Placeholder in case
// we use our own.
const char kV2PrecertificateCmsContentTypeOID[] = "1.3.6.1.4.1.11129.2.4.8";

static const char kPrecertificateRedactedLabelCountSN[] = "ctPreredact";
static const char kPrecertificateRedactedLabelCountLN[] =
    "Certificate Transparency "
    "Precertificate Redacted Label Count";
static const char kNameConstraintNologIntermediateSN[] =
    "ctNoLogIntermediateOk";
static const char kNameConstraintNologIntermediateLN[] =
    "Certificate Transparency "
    "Name Constrained Intermediate CA NoLog Allowed";
static const char kV2PrecertCmsContentTypeSN[] = "ctV2PrecertCmsContentType";
static const char kV2PrecertCmsContentTypeLN[] =
    "Certificate Transparency "
    "V2 Precertificate CMS Message Content Type";

static const char kASN1NullValue[] = "NULL";

// String conversion for an ASN1 NULL
static char* ASN1NullToString(X509V3_EXT_METHOD*, ASN1_NULL* asn1_null) {
  if (asn1_null == NULL)
    return NULL;
  char* buf = OPENSSL_strdup(kASN1NullValue);
  return buf;
}

// String conversion from an ASN1:NULL conf.
static ASN1_NULL* StringToASN1Null(X509V3_EXT_METHOD*, X509V3_CTX*,
                                   char* str) {
  if (str == NULL || strcmp(str, kASN1NullValue) != 0) {
    return NULL;
  }

  return ASN1_NULL_new();
}

// Not used in protocol v1. Specifies the count of redacted labels of each
// DNS id in the cert. See RFC section 3.2.2.
static X509V3_EXT_METHOD ct_redaction_count_method = {
    0,                         // ext_nid, NID, will be created by OBJ_create()
    0,                         // flags
    ASN1_ITEM_ref(REDACTED_LABEL_COUNT),
    0, 0, 0, 0,                // ignored since the above is set
    // Create from, and print to, a hex string
    // Allows to specify the extension configuration like so:
    // ctPreredact = "NULL"
    // (Unused, as we're not issuing certs.)
    reinterpret_cast<X509V3_EXT_I2S>(i2s_ASN1_OCTET_STRING),
    reinterpret_cast<X509V3_EXT_S2I>(s2i_ASN1_OCTET_STRING), 0, 0, 0, 0,
    NULL  // usr_data
};

// Not used in protocol v1. Specifies consent that name constrained
// intermediate certs may not be logged. See RFC section 3.2.3.
static X509V3_EXT_METHOD ct_name_constraint_nolog_intermediate_ca_method = {
    0,                         // ext_nid, NID, will be created by OBJ_create()
    0,                         // flags
    ASN1_ITEM_ref(ASN1_NULL),  // the object is an ASN1 NULL
    0, 0, 0, 0,                // ignored since the above is set
    // Create from, and print to, a hex string
    // Allows to specify the extension configuration like so:
    // ctPoison = "NULL"
    // (Unused, as we're not issuing certs.)
    reinterpret_cast<X509V3_EXT_I2S>(ASN1NullToString),
    reinterpret_cast<X509V3_EXT_S2I>(StringToASN1Null), 0, 0, 0, 0,
    NULL  // usr_data
};
// clang-format on

void LoadCtExtensions() {
  // V1 Certificate Extensions are built in to OpenSSL

  // V2 Certificate extensions

  ct_redaction_count_method.ext_nid =
      OBJ_create(kPrecertificateRedactedLabelOID,
                 kPrecertificateRedactedLabelCountSN,
                 kPrecertificateRedactedLabelCountLN);
  CHECK_NE(ct_redaction_count_method.ext_nid, 0);
  CHECK_EQ(1, X509V3_EXT_add(&ct_redaction_count_method));
  NID_ctPrecertificateRedactedLabelCount = ct_redaction_count_method.ext_nid;

  ct_name_constraint_nolog_intermediate_ca_method.ext_nid =
      OBJ_create(kNameConstraintNologIntermediateOID,
                 kNameConstraintNologIntermediateSN,
                 kNameConstraintNologIntermediateLN);
  CHECK_NE(ct_name_constraint_nolog_intermediate_ca_method.ext_nid, 0);
  CHECK_EQ(1,
           X509V3_EXT_add(&ct_name_constraint_nolog_intermediate_ca_method));
  NID_ctNameConstraintNologIntermediateCa =
      ct_name_constraint_nolog_intermediate_ca_method.ext_nid;

  // V2 Content types

  NID_ctV2CmsPayloadContentType =
      OBJ_create(kV2PrecertificateCmsContentTypeOID,
                 kV2PrecertCmsContentTypeSN, kV2PrecertCmsContentTypeLN);
}

}  // namespace cert_trans
