#include <gtest/gtest.h>

#include <pcap.h>

#include "EthLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"

#include "ip_signature.h"
#include "internal_structs.h"


namespace flow_inspector::internal {


struct TestPacket {
  ::pcpp::EthLayer eth_layer;
  ::pcpp::IPv4Layer ip_layer;
  ::pcpp::Packet packet{100};
};

TestPacket createTestPacket(const ::std::string& srcIp, const ::std::string& dstIp) {
  TestPacket test_packet{
    ::pcpp::EthLayer(pcpp::MacAddress("aa:bb:cc:dd:ee:ff"), ::pcpp::MacAddress("ff:ee:dd:cc:bb:aa")),
    ::pcpp::IPv4Layer(pcpp::IPv4Address(srcIp), ::pcpp::IPv4Address(dstIp))
  };

  test_packet.packet.addLayer(&test_packet.eth_layer);
  test_packet.packet.addLayer(&test_packet.ip_layer);
  test_packet.packet.computeCalculateFields();

  return test_packet;
}

TEST(IPSignatureTest, SingleIPMatch) {
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> srcIps = {{ipToUInt("192.168.1.1"), getMaskByLen(32)}};
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> dstIps = {{ipToUInt("10.0.0.1"), getMaskByLen(32)}};
  
  IPSignature signature(srcIps, dstIps);
  auto testPacket = createTestPacket("192.168.1.1", "10.0.0.1");

  EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket(), true}));
}

TEST(IPSignatureTest, NoIPMatch) {
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> srcIps = {{ipToUInt("192.168.1.1"), getMaskByLen(32)}};
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> dstIps = {{ipToUInt("10.0.0.1"), getMaskByLen(32)}};
  
  IPSignature signature(srcIps, dstIps);
  auto testPacket = createTestPacket("192.168.1.2", "10.0.0.2");

  EXPECT_FALSE(signature.check(Packet{*testPacket.packet.getRawPacket(), true}));
}

TEST(IPSignatureTest, SingleMatchWithEmptyDestinationSet) {
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> srcIps = {{ipToUInt("192.168.1.1"), getMaskByLen(32)}};

  IPSignature signature(srcIps, ::std::unordered_set<::std::pair<uint32_t, uint32_t>>{});
  auto testPacket = createTestPacket("192.168.1.1", "10.0.0.1");

  EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket(), true}));
}

TEST(IPSignatureTest, SingleMatchWithEmptySourceSet) {
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> dstIps = {{ipToUInt("10.0.0.1"), getMaskByLen(32)}};

  IPSignature signature(::std::unordered_set<::std::pair<uint32_t, uint32_t>>{}, dstIps);
  auto testPacket = createTestPacket("192.168.1.2", "10.0.0.1");

  EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket(), true}));
}

TEST(IPSignatureTest, SingleIPMatchFromSet) {
  const ::std::string srcIp1 = "192.168.1.1";
  const ::std::string srcIp2 = "192.168.1.4";
  const ::std::string dstIp1 = "10.0.0.1";
  const ::std::string dstIp2 = "10.0.0.2";
  ::std::string sigStr = "([" + srcIp1 + "/32, " + srcIp2 + "/32], [" + dstIp1 + "/32, " + dstIp2 + "/32])";

  auto signature = IPSignature::createIPSignature(sigStr);

  {
    auto testPacket = createTestPacket("192.168.1.1", "10.0.0.1");
    EXPECT_TRUE(signature->check(Packet{*testPacket.packet.getRawPacket(), true}));
  }

  {
    auto testPacket = createTestPacket("192.168.2.1", "10.0.0.1");
    EXPECT_FALSE(signature->check(Packet{*testPacket.packet.getRawPacket(), true}));
  }

  {
    auto testPacket = createTestPacket("192.168.1.1", "10.0.0.2");
    EXPECT_TRUE(signature->check(Packet{*testPacket.packet.getRawPacket(), true}));
  }
}

TEST(IPSignatureTest, CIDRMatch) {
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> srcIps = {{ipToUInt("192.168.1.0"), getMaskByLen(24)}};
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> dstIps = {{ipToUInt("10.0.0.0"), getMaskByLen(24)}};

  IPSignature signature(srcIps, dstIps);

  {
    auto testPacket = createTestPacket("192.168.1.5", "10.0.0.10");
    EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket(), true}));
  }

  {
    auto testPacket = createTestPacket("192.168.2.5", "10.0.1.10");
    EXPECT_FALSE(signature.check(Packet{*testPacket.packet.getRawPacket(), true}));
  }
}

}  // namespace flow_inspector::internal
