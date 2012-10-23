#include <glog/logging.h>
#include <gtest/gtest.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string>

#include "ct.pb.h"
#include "log_signer.h"
#include "serial_hasher.h"
#include "serializer.h"
#include "test_signer.h"
#include "util.h"

namespace {

using ct::DigitallySigned;
using ct::LogEntry;
using ct::LoggedCertificate;
using ct::PrecertChainEntry;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using ct::X509ChainEntry;
using std::string;

// A slightly shorter notation for constructing binary blobs from test vectors.
string B(const char *hexstring) {
  return util::BinaryString(hexstring);
}

// A slightly shorter notation for constructing hex strings from binary blobs.
std::string H(const std::string &byte_string) {
  return util::HexString(byte_string);
}

const char kDefaultDerCert[] =
    "308202ca30820233a003020102020102300d06092a864886f70d01010505003055310b3009"
    "06035504061302474231243022060355040a131b4365727469666963617465205472616e73"
    "706172656e6379204341310e300c0603550408130557616c65733110300e06035504071307"
    "4572772057656e301e170d3132303630313030303030305a170d3232303630313030303030"
    "305a3052310b30090603550406130247423121301f060355040a1318436572746966696361"
    "7465205472616e73706172656e6379310e300c0603550408130557616c65733110300e0603"
    "55040713074572772057656e30819f300d06092a864886f70d010101050003818d00308189"
    "02818100b8742267898b99ba6bfd6e6f7ada8e54337f58feb7227c46248437ba5f89b007cb"
    "e1ecb4545b38ed23fddbf6b9742cafb638157f68184776a1b38ab39318ddd734489b4d7501"
    "17cd83a220a7b52f295d1e18571469a581c23c68c57d973761d9787a091fb5864936b16653"
    "5e21b427e3c6d690b2e91a87f36b7ec26f59ce53b50203010001a381ac3081a9301d060355"
    "1d0e041604141184e1187c87956dffc31dd0521ff564efbeae8d307d0603551d2304763074"
    "8014a3b8d89ba2690dfb48bbbf87c1039ddce56256c6a159a4573055310b30090603550406"
    "1302474231243022060355040a131b4365727469666963617465205472616e73706172656e"
    "6379204341310e300c0603550408130557616c65733110300e060355040713074572772057"
    "656e82010030090603551d1304023000300d06092a864886f70d010105050003818100292e"
    "cf6e46c7a0bcd69051739277710385363341c0a9049637279707ae23cc5128a4bdea0d480e"
    "d0206b39e3a77a2b0c49b0271f4140ab75c1de57aba498e09459b479cf92a4d5d5dd5cbe3f"
    "0a11e25f04078df88fc388b61b867a8de46216c0e17c31fc7d8003ecc37be22292f84242ab"
    "87fb08bd4dfa3c1b9ce4d3ee6667da";

const char kDefaultDerCertHash[] =
    "50335d9cd3649871d0c95397648bf7814c297b3bad7020b2c13d2b0aef6e3b49";

// Some time in September 2012.
const uint64_t kDefaultSCTTimestamp = 1348589665525LL;

const char kDefaultSCTSignature[] =
    "3046022100e164999c0b7aa7a2d9f73264023663b48c646550f0587a6e044aba2fa608152d"
    "0221008abf2906f17732c8707e559270121921026f266cded2e130a46bb60016bc519b";

// Some time in September 2012.
const uint64_t kDefaultSTHTimestamp = 1348589667204LL;

const uint64_t kDefaultTreeSize = 42;

// *Some* hash that we pretend is a valid root hash.
const char kDefaultRootHash[] =
    "18041bd4665083001fba8c5411d2d748e8abbfdcdfd9218cb02b68a78e7d4c23";

const char kDefaultSTHSignature[] =
    "3045022066ab4e7eaad1961c34448ed5dd37959bed95476fc02476def57c63a91b52445c02"
    "21009887b36a965e04e196753fac4a15cffbb86770bfacf74dfe6e259c967904fecc";

const char kEcP256PrivateKey[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIG8QAquNnarN6Ik2cMIZtPBugh9wNRe0e309MCmDfBGuoAoGCCqGSM49\n"
    "AwEHoUQDQgAES0AfBkjr7b8b19p5Gk8plSAN16wWXZyhYsH6FMCEUK60t7pem/ck\n"
    "oPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n"
    "-----END EC PRIVATE KEY-----\n";

const char kEcP256PublicKey[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAES0AfBkjr7b8b19p5Gk8plSAN16wW\n"
    "XZyhYsH6FMCEUK60t7pem/ckoPX8hupuaiJzJS0ZQ0SEoJGlFxkUFwft5g==\n"
    "-----END PUBLIC KEY-----\n";

EVP_PKEY* PrivateKeyFromPem(const string &pemkey) {
  // BIO_new_mem_buf is read-only.
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

EVP_PKEY* PublicKeyFromPem(const string &pemkey) {
  BIO *bio = BIO_new_mem_buf(const_cast<char*>(pemkey.data()), pemkey.size());
  EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  assert(pkey != NULL);
  BIO_free(bio);
  return pkey;
}

}  // namespace

TestSigner::TestSigner()
    : default_signer_(NULL),
      counter_(0),
      default_cert_(B(kDefaultDerCert)) {
  counter_ = util::TimeInMilliseconds();
  srand(counter_);
  EVP_PKEY *pkey = PrivateKeyFromPem(kEcP256PrivateKey);
  CHECK_NOTNULL(pkey);
  default_signer_ = new LogSigner(pkey);
}

TestSigner::~TestSigner() {
  delete default_signer_;
}

// Caller owns result.
// Call as many times as required to get a fresh copy every time.
// static
LogSigner *TestSigner::DefaultSigner() {
  EVP_PKEY *pkey = PrivateKeyFromPem(kEcP256PrivateKey);
  CHECK_NOTNULL(pkey);
  return new LogSigner(pkey);
}

// Caller owns result.
// Call as many times as required to get a fresh copy every time.
// static
LogSigVerifier *TestSigner::DefaultVerifier() {
  EVP_PKEY *pubkey = PublicKeyFromPem(kEcP256PublicKey);
  CHECK_NOTNULL(pubkey);
  return new LogSigVerifier(pubkey);
}

// static
void TestSigner::SetDefaults(LogEntry *entry) {
  entry->set_type(ct::X509_ENTRY);
  entry->mutable_x509_entry()->set_leaf_certificate(B(kDefaultDerCert));
}

// static
void TestSigner::SetDefaults(SignedCertificateTimestamp *sct) {
  sct->set_timestamp(kDefaultSCTTimestamp);
  sct->mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
  sct->mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
  sct->mutable_signature()->set_signature(B(kDefaultSCTSignature));
}

// static
void TestSigner::SetDefaults(LoggedCertificate *logged_cert) {
  // Some time in September 2012.
  SetDefaults(logged_cert->mutable_sct());
  SetDefaults(logged_cert->mutable_entry());
  // FIXME(ekasper): don't assume SHA256 in test vectors
  // (despite the field name).
  logged_cert->set_certificate_sha256_hash(B(kDefaultDerCertHash));
}

// static
void TestSigner::SetDefaults(SignedTreeHead *tree_head) {
  tree_head->set_timestamp(kDefaultSTHTimestamp);
  tree_head->set_tree_size(kDefaultTreeSize);
  tree_head->set_root_hash(B(kDefaultRootHash));
  tree_head->mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
  tree_head->mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
  tree_head->mutable_signature()->set_signature(B(kDefaultSTHSignature));
}

string TestSigner::UniqueFakeCertBytestring() {
  string counter_suffix = Serializer::SerializeUint(counter_++, 8);
  int length = (rand() % 512) + 512 - counter_suffix.size();

  string ret;
  while (length >= 256) {
    unsigned offset = rand() & 0xff;
    DCHECK_LE(offset + 256, default_cert_.size());
    ret.append(default_cert_.substr(offset, 256));
    length -=256;
  }

  if (length > 0) {
    int offset = rand() & 0xff;
    ret.append(default_cert_.substr(offset, length));
  }

  ret.append(counter_suffix);
  return ret;
}

string TestSigner::UniqueHash() {
  string counter = Serializer::SerializeUint(counter_++, 8);
  return Sha256Hasher::Sha256Digest(counter);
}

void TestSigner::CreateUnique(LogEntry *entry) {
  int random_bits = rand();
  ct::LogEntryType type = random_bits & 1 ?
      ct::X509_ENTRY : ct::PRECERT_ENTRY;

  entry->set_type(type);
  entry->clear_x509_entry();
  entry->clear_precert_entry();

  if (type == ct::X509_ENTRY) {
    entry->mutable_x509_entry()->set_leaf_certificate(
        UniqueFakeCertBytestring());
    if (random_bits & 2) {
      entry->mutable_x509_entry()->add_certificate_chain(
          UniqueFakeCertBytestring());

      if (random_bits & 4) {
        entry->mutable_x509_entry()->add_certificate_chain(
            UniqueFakeCertBytestring());
      }
    }
  } else {
    entry->mutable_precert_entry()->set_tbs_certificate(
        UniqueFakeCertBytestring());
    if (random_bits & 2) {
      entry->mutable_precert_entry()->add_precertificate_chain(
          UniqueFakeCertBytestring());

      if (random_bits & 4) {
        entry->mutable_precert_entry()->add_precertificate_chain(
            UniqueFakeCertBytestring());
      }
    }
  }
}

void TestSigner::CreateUnique(LoggedCertificate *logged_cert) {
  FillData(logged_cert);

  CHECK_EQ(LogSigner::OK,
           default_signer_->SignCertificateTimestamp(
               logged_cert->entry(),
               logged_cert->mutable_sct()));
}

void TestSigner::CreateUniqueFakeSignature(LoggedCertificate *logged_cert) {
  FillData(logged_cert);

  logged_cert->mutable_sct()->mutable_signature()->set_hash_algorithm(
      DigitallySigned::SHA256);
  logged_cert->mutable_sct()->mutable_signature()->set_sig_algorithm(
      DigitallySigned::ECDSA);
  logged_cert->mutable_sct()->mutable_signature()->set_signature(
      B(kDefaultSCTSignature));
}

void TestSigner::CreateUnique(SignedTreeHead *sth) {
  sth->set_timestamp(util::TimeInMilliseconds());
  sth->set_tree_size(rand());
  sth->set_root_hash(UniqueHash());
  CHECK_EQ(LogSigner::OK,
           default_signer_->SignTreeHead(sth));
}

// static
void TestSigner::TestEqualDigitallySigned(const DigitallySigned &ds0,
                                          const DigitallySigned &ds1) {
  EXPECT_EQ(ds0.hash_algorithm(), ds1.hash_algorithm());
  EXPECT_EQ(ds0.sig_algorithm(), ds1.sig_algorithm());
  EXPECT_EQ(H(ds0.signature()), H(ds1.signature()));
}

// static
void TestSigner::TestEqualX509Entries(const X509ChainEntry &entry0,
                                      const X509ChainEntry &entry1) {
  EXPECT_EQ(H(entry0.leaf_certificate()), H(entry1.leaf_certificate()));
  EXPECT_EQ(entry0.certificate_chain_size(), entry1.certificate_chain_size());
  for (int i = 0; i < entry0.certificate_chain_size(); ++i)
    EXPECT_EQ(H(entry0.certificate_chain(i)), H(entry1.certificate_chain(i)));
}

// static
void TestSigner::TestEqualPreEntries(const PrecertChainEntry &entry0,
                                     const PrecertChainEntry &entry1) {
  EXPECT_EQ(H(entry0.tbs_certificate()), H(entry1.tbs_certificate()));
  EXPECT_EQ(entry0.precertificate_chain_size(),
            entry1.precertificate_chain_size());
  for (int i = 0; i < entry0.precertificate_chain_size(); ++i)
    EXPECT_EQ(H(entry0.precertificate_chain(i)),
              H(entry1.precertificate_chain(i)));
}

// static
void TestSigner::TestEqualEntries(const LogEntry &entry0,
                                  const LogEntry &entry1) {
  EXPECT_EQ(entry0.type(), entry1.type());
  if (entry0.type() == ct::X509_ENTRY)
    TestEqualX509Entries(entry0.x509_entry(), entry1.x509_entry());
  if (entry1.type() == ct::PRECERT_ENTRY)
    TestEqualPreEntries(entry0.precert_entry(), entry1.precert_entry());
}

// static
void TestSigner::TestEqualSCTs(const SignedCertificateTimestamp &sct0,
                               const SignedCertificateTimestamp &sct1) {
  EXPECT_EQ(sct0.timestamp(), sct1.timestamp());
  TestEqualDigitallySigned(sct0.signature(), sct1.signature());
}

// static
void TestSigner::TestEqualLoggedCerts(const LoggedCertificate &c0,
                                      const LoggedCertificate &c1) {
  TestEqualEntries(c0.entry(), c1.entry());
  TestEqualSCTs(c0.sct(), c1.sct());

  EXPECT_EQ(H(c0.certificate_sha256_hash()),
            H(c1.certificate_sha256_hash()));
  EXPECT_EQ(c0.has_sequence_number(), c1.has_sequence_number());
  // Defaults to 0 if not set.
  EXPECT_EQ(c0.sequence_number(), c1.sequence_number());
}

// static
void TestSigner::TestEqualTreeHeads(const SignedTreeHead &sth0,
                                    const SignedTreeHead &sth1) {
  EXPECT_EQ(sth0.tree_size(), sth1.tree_size());
  EXPECT_EQ(sth0.timestamp(), sth1.timestamp());
  EXPECT_EQ(H(sth0.root_hash()), H(sth1.root_hash()));
  TestEqualDigitallySigned(sth0.signature(), sth1.signature());
}

void TestSigner::FillData(LoggedCertificate *logged_cert) {
  logged_cert->mutable_sct()->set_timestamp(util::TimeInMilliseconds());

  CreateUnique(logged_cert->mutable_entry());

  logged_cert->set_certificate_sha256_hash(
      Serializer::CertificateSha256Hash(logged_cert->entry()));

  logged_cert->clear_sequence_number();
}
