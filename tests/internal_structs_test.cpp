#include <gtest/gtest.h>
#include "internal_structs.h"


namespace flow_inspector::internal {


TEST(PacketTest, WithEmptyVector) {
  std::vector<byte> emptyData;
  Packet packet(emptyData);
  
  EXPECT_EQ(packet.toString(), "[]");
}

TEST(PacketTest, WithNonEmptyVector) {
  std::vector<byte> data = {1, 2, 3, 4, 5};
  Packet packet(data);
  
  EXPECT_EQ(packet.toString(), "[1 2 3 4 5]");
}


TEST(AlertTest, WithMessage) {
  const std::string testMessage = "Test alert message";
  Alert alert(testMessage);
  
  EXPECT_EQ(alert.toString(), testMessage);
}

TEST(AlertTest, WithEmptyMessage) {
  const std::string emptyMessage = "";
  Alert alert(emptyMessage);
  
  EXPECT_EQ(alert.toString(), emptyMessage);
}

TEST(AlertTest, WithVeryLongMessage) {
  std::string longMessage(10000, 'a');
  Alert alert(longMessage);
  
  EXPECT_EQ(alert.toString(), longMessage);
  EXPECT_EQ(alert.toString().length(), 10000);
}


TEST(SignatureTest, ConstructorWithEmptyPayload) {
  std::vector<byte> emptyPayload;
  Signature signature(emptyPayload);
  
  Packet packet({1, 2, 3, 4, 5});
  EXPECT_TRUE(signature.Check(packet));
}


TEST(SignatureTest, ConstructorWithNonEmptyPayload) {
  std::vector<byte> payload = {1, 2, 3, 4, 5};
  Signature signature(payload);
  
  Packet packet({0, 1, 2, 3, 4, 5, 6});
  EXPECT_TRUE(signature.Check(packet));
  
  Packet nonMatchingPacket({0, 1, 2, 3, 6, 7, 8});
  EXPECT_FALSE(signature.Check(nonMatchingPacket));
}


TEST(SignatureTest, ConstructorWithPayloadAndOffset) {
  std::vector<byte> payload = {2, 3, 4};
  uint32_t offset = 1;
  Signature signature(payload, offset);
  
  Packet matchingPacket({1, 2, 3, 4, 5});
  EXPECT_TRUE(signature.Check(matchingPacket));
  
  Packet nonMatchingPacket({1, 1, 2, 3, 4, 5});
  EXPECT_FALSE(signature.Check(nonMatchingPacket));
  
  Packet shortPacket({1, 2});
  EXPECT_FALSE(signature.Check(shortPacket));
}


TEST(SignatureTest, CheckWithOffsetBeyondPacketSize) {
  std::vector<byte> payload = {1, 2, 3};
  uint32_t offset = 10;
  Signature signature(payload, offset);
  
  Packet packet({1, 2, 3, 4, 5});
  EXPECT_FALSE(signature.Check(packet));
}


}  // namespace flow_inspector::internal
