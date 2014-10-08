#ifndef CT_EXTENSIONS_H
#define CT_EXTENSIONS_H

namespace cert_trans {

// One-time initializer for loading CT-specific certificate extensions.
void LoadCtExtensions();

// Numerical identifiers.
// You must call LoadCtExtensions() for these to work.
extern int NID_ctSignedCertificateTimestampList;
extern int NID_ctEmbeddedSignedCertificateTimestampList;
extern int NID_ctPoison;
extern int NID_ctPrecertificateSigning;

// The official CT OIDs
// The SCT list in the extension of a superfluous certificate
extern const char kSCTListOID[];
// The SCT list embedded in the certificate itself
extern const char kEmbeddedSCTListOID[];
// The poison extension
extern const char kPoisonOID[];
// Extended Key Usage value for Precertificate signing
extern const char kPrecertificateSigningOID[];

}  // namespace cert_trans

#endif  // CT_EXTENSIONS_H
