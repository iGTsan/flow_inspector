#include <gtest/gtest.h>
#include "internal_structs.h"


namespace flow_inspector::internal {


TEST(PacketTest, WithEmptyVector) {
  ::std::vector<byte> emptyData;
  Packet packet(emptyData);
  
  EXPECT_EQ(packet.toString(), "[]");
}

TEST(PacketTest, WithNonEmptyVector) {
  ::std::vector<byte> data = {1, 2, 3, 4, 5};
  Packet packet(data);
  
  EXPECT_EQ(packet.toString(), "[1 2 3 4 5]");
}


TEST(AlertTest, WithMessage) {
  const ::std::string testMessage = "Test alert message";
  Alert alert(testMessage);
  
  EXPECT_EQ(alert.toString(), testMessage);
}

TEST(AlertTest, WithEmptyMessage) {
  const ::std::string emptyMessage = "";
  Alert alert(emptyMessage);
  
  EXPECT_EQ(alert.toString(), emptyMessage);
}

TEST(AlertTest, WithVeryLongMessage) {
  ::std::string longMessage(10000, 'a');
  Alert alert(longMessage);
  
  EXPECT_EQ(alert.toString(), longMessage);
  EXPECT_EQ(alert.toString().length(), 10000);
}


TEST(SignatureTest, ConstructorWithEmptyPayload) {
  ::std::vector<byte> emptyPayload;
  Signature signature(emptyPayload);
  
  Packet packet{::std::vector<byte>{1, 2, 3, 4, 5}};
  EXPECT_TRUE(signature.check(packet));
}


TEST(SignatureTest, ConstructorWithNonEmptyPayload) {
  ::std::vector<byte> payload = {1, 2, 3, 4, 5};
  Signature signature(payload);
  
  Packet matchingPacket{::std::vector<byte>{0, 1, 2, 3, 4, 5, 6}};
  EXPECT_TRUE(signature.check(matchingPacket));
  
  Packet nonMatchingPacket{::std::vector<byte>{0, 1, 2, 3, 6, 8}};
  EXPECT_FALSE(signature.check(nonMatchingPacket));
}


TEST(SignatureTest, ConstructorWithPayloadAndOffset) {
  ::std::vector<byte> payload = {2, 3, 4};
  uint32_t offset = 1;
  Signature signature(payload, offset);
  
  Packet matchingPacket{::std::vector<byte>{1, 2, 3, 4, 5}};
  EXPECT_TRUE(signature.check(matchingPacket));
  
  Packet nonMatchingPacket{::std::vector<byte>{1, 1, 2, 3, 4, 5}};
  EXPECT_FALSE(signature.check(nonMatchingPacket));
  
  Packet shortPacket{::std::vector<byte>{1, 2}};
  EXPECT_FALSE(signature.check(shortPacket));
}


TEST(SignatureTest, CheckWithOffsetBeyondPacketSize) {
  ::std::vector<byte> payload = {1, 2, 3};
  uint32_t offset = 10;
  Signature signature(payload, offset);
  
  
  Packet packet{::std::vector<byte>{1, 2, 3, 4, 5}};
  EXPECT_FALSE(signature.check(packet));
}


TEST(RuleTest, ConstructorWithValidNameAndEventType) {
  const ::std::string testName = "TestRule";
  const Event::EventType testType = Event::EventType::TestEvent;
  
  Rule rule(testName, testType);
  
  EXPECT_EQ(rule.getName(), testName);
  EXPECT_EQ(rule.getType(), testType);
}


TEST(RuleTest, AddSignatureWithValidPointer) {
  Rule rule("TestRule", Event::EventType::Alert);
  
  std::vector<byte> payload = {1, 2, 3, 4, 5};
  const auto signature = std::make_unique<Signature>(payload);
  
  rule.addSignature(signature.get());
  
  Packet matchingPacket({0, 1, 2, 3, 4, 5, 6});
  EXPECT_TRUE(rule.check(matchingPacket));
  
  Packet nonMatchingPacket({0, 1, 2, 3, 6, 7});
  EXPECT_FALSE(rule.check(nonMatchingPacket));
}


TEST(RuleTest, CheckReturnsTrueForEmptySignatures) {
  Rule rule("TestRule", Event::EventType::Alert);
  Packet packet(::std::vector<byte>{1, 2, 3, 4, 5});

  EXPECT_TRUE(rule.check(packet));
}


TEST(RuleTest, CheckMultipleMatchingSignatures) {
  Rule rule("TestRule", Event::EventType::Alert);

  ::std::vector<byte> payload1 = {1, 2, 3};
  ::std::vector<byte> payload2 = {4, 5, 6};
  Signature sig1(payload1);
  Signature sig2(payload2);

  rule.addSignature(&sig1);
  rule.addSignature(&sig2);

  ::std::vector<byte> packetData = {0, 1, 2, 3, 4, 5, 6, 7};
  Packet packet(packetData);

  EXPECT_TRUE(rule.check(packet));
}


TEST(RuleTest, CheckWithMultipleSignaturesOneNotMatching) {
  Rule rule("TestRule", Event::EventType::Alert);

  ::std::vector<byte> payload1 = {1, 2, 3};
  ::std::vector<byte> payload2 = {4, 5, 6};
  ::std::vector<byte> payload3 = {7, 8, 9};

  Signature sig1(::std::move(payload1));
  Signature sig2(::std::move(payload2));
  Signature sig3(::std::move(payload3));

  rule.addSignature(&sig1);
  rule.addSignature(&sig2);
  rule.addSignature(&sig3);

  Packet matchingPacket(::std::vector<byte>{0, 1, 2, 3, 4, 5, 6, 10, 11});
  Packet nonMatchingPacket(::std::vector<byte>{0, 1, 2, 3, 4, 5, 6, 10, 11, 12});

  EXPECT_FALSE(rule.check(matchingPacket));
  EXPECT_FALSE(rule.check(nonMatchingPacket));
}


}  // namespace flow_inspector::internal
