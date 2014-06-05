#include "util/json_wrapper.h"

#include "util/testing.h"
#include "util/util.h"

#include <gtest/gtest.h>

class JsonWrapperTest : public ::testing::Test {
};

TEST_F(JsonWrapperTest, LargeInt) {
  int64_t big = 0x123456789aLL;
  json_object *jint = json_object_new_int64(big);
  const char *jsoned = json_object_to_json_string(jint);
  JsonInt jint2(json_tokener_parse(jsoned));
  CHECK_EQ(big, jint2.Value());
}

TEST_F(JsonWrapperTest, UnwrapResponse) {
  static std::string response("{\"leaf_index\":3,\"audit_path\":"
      "[\"j17CTFWsQGwnQkYsebYS7CondFpbzIo+N1jPi9UrqTI=\","
  "\"QSNVV8/waZ5rezVSTFcSPbKtqjalAwVqdF2Vv0/l3/Q=\"]}");
  static std::string p1v(
      "8f5ec24c55ac406c2742462c79b612ec2a27745a5bcc8a3e3758cf8bd52ba932");
  static std::string p2v(
      "41235557cff0699e6b7b35524c57123db2adaa36a503056a745d95bf4fe5dff4");

  JsonObject jresponse(response);
  ASSERT_TRUE(jresponse.Ok());

  JsonInt leaf_index(jresponse, "leaf_index");
  ASSERT_TRUE(leaf_index.Ok());
  EXPECT_EQ(leaf_index.Value(), 3);

  JsonArray audit_path(jresponse, "audit_path");
  ASSERT_TRUE(audit_path.Ok());
  EXPECT_EQ(audit_path.Length(), 2);

  JsonString p1(audit_path, 0);
  ASSERT_TRUE(p1.Ok());
  EXPECT_EQ(util::HexString(p1.FromBase64()), p1v);

  JsonString p2(audit_path, 1);
  ASSERT_TRUE(p2.Ok());
  EXPECT_EQ(util::HexString(p2.FromBase64()), p2v);
}

int main(int argc, char**argv) {
  ct::test::InitTesting(argv[0], &argc, &argv, true);
  return RUN_ALL_TESTS();
}
