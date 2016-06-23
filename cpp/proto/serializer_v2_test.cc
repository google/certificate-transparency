/* -*- indent-tabs-mode: nil -*- */
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/repeated_field.h>
#include <gtest/gtest.h>
#include <string>

#include "proto/cert_serializer.h"
#include "proto/ct.pb.h"
#include "proto/serializer_v2.h"
#include "util/testing.h"
#include "util/util.h"

namespace {

const char kOID[] = "1.2.3.4.5";
const char kOIDTagMissingDERHex[] = "042a030405";

using rfc6962_bis::OID;
using std::string;

class SerializerV2Test : public ::testing::Test {
 public:
  SerializerV2Test() {
    oid_text_ = std::string(kOID);
    oid_der_missing_tag_ = util::BinaryString(kOIDTagMissingDERHex);
  }
 protected:
  string oid_text_;
  string oid_der_missing_tag_;
};

TEST_F(SerializerV2Test, SerializesSimpleOID) {
  util::StatusOr<OID> res = OID::FromString(oid_text_);
  ASSERT_TRUE(res.ok());

  string encoded_der = res.ValueOrDie().ToTagMissingDER().ValueOrDie();
  EXPECT_EQ(oid_der_missing_tag_, encoded_der);
}

TEST_F(SerializerV2Test, FailsOnInvalidOID) {
  string bad_oid("3.7.-12.b");

  util::StatusOr<OID> res = OID::FromString(bad_oid);
  ASSERT_FALSE(res.ok());
}

TEST_F(SerializerV2Test, CreatesFromTagMissingDER) {
  util::StatusOr<OID> res = OID::FromTagMissingDER(oid_der_missing_tag_);

  ASSERT_TRUE(res.ok());
  EXPECT_EQ(oid_text_, res.ValueOrDie().ToString());
}

}  // namespace

int main(int argc, char** argv) {
  cert_trans::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
