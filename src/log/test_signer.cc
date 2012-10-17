#include <glog/logging.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string>

#include "ct.pb.h"
#include "log_signer.h"
#include "serializer.h"
#include "test_signer.h"
#include "util.h"

#include "serial_hasher.h"

namespace {

using ct::CertificateEntry;
using ct::DigitallySigned;
using ct::LoggedCertificate;
using ct::SignedCertificateTimestamp;
using ct::SignedTreeHead;
using std::string;

// A slightly shorter notation for constructing binary blobs from test vectors.
string B(const char *hexstring) {
  return util::BinaryString(hexstring);
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
    "3044022041dc1ec2dd47ad84bd1da5f88cf5bf0516476cd7822f1f5e8f59e624ee259a1d02"
    "20522f61d5b0e6d00aa9fff2589e9918dfa8af3faa312ea037a20bc762f71c337c";

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
//static
LogSigVerifier *TestSigner::DefaultVerifier() {
  EVP_PKEY *pubkey = PublicKeyFromPem(kEcP256PublicKey);
  CHECK_NOTNULL(pubkey);
  return new LogSigVerifier(pubkey);
}

// static
void TestSigner::SetDefaults(SignedCertificateTimestamp *sct) {
  sct->set_timestamp(kDefaultSCTTimestamp);
  sct->mutable_entry()->set_type(CertificateEntry::X509_ENTRY);
  sct->mutable_entry()->set_leaf_certificate(B(kDefaultDerCert));
  sct->mutable_signature()->set_hash_algorithm(DigitallySigned::SHA256);
  sct->mutable_signature()->set_sig_algorithm(DigitallySigned::ECDSA);
  sct->mutable_signature()->set_signature(B(kDefaultSCTSignature));
}

// static
void TestSigner::SetDefaults(LoggedCertificate *logged_cert) {
  // Some time in September 2012.
  SetDefaults(logged_cert->mutable_sct());
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

void TestSigner::CreateUnique(CertificateEntry *entry) {
  entry->set_leaf_certificate(UniqueFakeCertBytestring());
  int random_bits = rand();
  CertificateEntry::Type type = random_bits & 1 ?
      CertificateEntry::X509_ENTRY : CertificateEntry::PRECERT_ENTRY;

  entry->set_type(type);

  entry->clear_intermediates();
  if (random_bits & 2) {
    entry->add_intermediates(UniqueFakeCertBytestring());

    if (random_bits & 4) {
      entry->add_intermediates(UniqueFakeCertBytestring());
    }
  }
}

void TestSigner::CreateUnique(LoggedCertificate *logged_cert) {
  FillData(logged_cert);

  CHECK_EQ(LogSigner::OK,
           default_signer_->SignCertificateTimestamp(
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

void TestSigner::FillData(LoggedCertificate *logged_cert) {
  logged_cert->mutable_sct()->set_timestamp(util::TimeInMilliseconds());

  CreateUnique(logged_cert->mutable_sct()->mutable_entry());

  logged_cert->set_certificate_sha256_hash(Sha256Hasher::Sha256Digest(
      logged_cert->sct().entry().leaf_certificate()));

  logged_cert->clear_sequence_number();
}
