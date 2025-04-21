#include <gtest/gtest.h>
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "ip_signature.h"
#include "internal_structs.h"
#include <pcap.h>


namespace flow_inspector::internal {


struct TestPacket {
  ::pcpp::EthLayer eth_layer;
  ::pcpp::IPv4Layer ip_layer;
  ::pcpp::Packet packet{100};
};

TestPacket createTestPacket(const std::string& srcIp, const std::string& dstIp) {
  TestPacket test_packet {
    ::pcpp::EthLayer(pcpp::MacAddress("aa:bb:cc:dd:ee:ff"), ::pcpp::MacAddress("ff:ee:dd:cc:bb:aa")),
    ::pcpp::IPv4Layer(pcpp::IPv4Address(srcIp), ::pcpp::IPv4Address(dstIp)),
  };

  test_packet.packet.addLayer(&test_packet.eth_layer);
  test_packet.packet.addLayer(&test_packet.ip_layer);
  test_packet.packet.computeCalculateFields();

  return test_packet;
}

TEST(IPSignatureTest, SingleIPMatch) {
  ::std::unordered_set<::pcpp::IPv4Address> srcIps = {::pcpp::IPv4Address("192.168.1.1")};
  ::std::unordered_set<::pcpp::IPv4Address> dstIps = {::pcpp::IPv4Address("10.0.0.1")};
  
  IPSignature signature(srcIps, dstIps);
  auto testPacket = createTestPacket("192.168.1.1", "10.0.0.1");

  EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket()}));
}

TEST(IPSignatureTest, NoIPMatch) {
  ::std::unordered_set<::pcpp::IPv4Address> srcIps = {::pcpp::IPv4Address("192.168.1.1")};
  ::std::unordered_set<::pcpp::IPv4Address> dstIps = {::pcpp::IPv4Address("10.0.0.1")};
  
  IPSignature signature(srcIps, dstIps);
  auto testPacket = createTestPacket("192.168.1.2", "10.0.0.2");

  EXPECT_FALSE(signature.check(Packet{*testPacket.packet.getRawPacket()}));
}

TEST(IPSignatureTest, SingleMatchWithEmptyDestinationSet) {
  ::std::unordered_set<::pcpp::IPv4Address> srcIps = {::pcpp::IPv4Address("192.168.1.1")};

  IPSignature signature(srcIps, ::std::unordered_set<::pcpp::IPv4Address>{});
  auto testPacket = createTestPacket("192.168.1.1", "10.0.0.1");

  EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket()}));
}

TEST(IPSignatureTest, SingleMatchWithEmptySourceSet) {
  ::std::unordered_set<::pcpp::IPv4Address> dstIps = {::pcpp::IPv4Address("10.0.0.1")};

  IPSignature signature(::std::unordered_set<::pcpp::IPv4Address>{}, dstIps);
  auto testPacket = createTestPacket("192.168.1.2", "10.0.0.1");

  EXPECT_TRUE(signature.check(Packet{*testPacket.packet.getRawPacket()}));
}

TEST(IPSignatureTest, SingleIPMatchFromSet) {
  const ::std::string srcIp1 = "192.168.1.1";
  const ::std::string srcIp2 = "192.168.1.4";
  const ::std::string srcIp3 = "192.168.1.6";
  const ::std::string srcIp4 = "192.168.1.10";
  const ::std::string dstIp1 = "10.0.0.1";
  const ::std::string dstIp2 = "10.0.0.2";
  const ::std::string dstIp3 = "10.0.0.3";
  const ::std::string dstIp4 = "10.0.0.4";
  ::std::string sigStr = "([" + srcIp1 + ", " + srcIp2 +"], [" + dstIp1 + ", " + dstIp2 + "]";

  auto signature = IPSignature::createIPSignature(sigStr);

  {
    auto testPacket = createTestPacket("192.168.1.1", "10.0.0.1");
    EXPECT_TRUE(signature->check(Packet{*testPacket.packet.getRawPacket()}));
  }

  {
    auto testPacket = createTestPacket("192.168.2.1", "10.0.0.1");
    EXPECT_FALSE(signature->check(Packet{*testPacket.packet.getRawPacket()}));
  }

  {
    auto testPacket = createTestPacket("192.168.1.1", "10.0.0.2");
    EXPECT_TRUE(signature->check(Packet{*testPacket.packet.getRawPacket()}));
  }
}


}  // namespace flow_inspector::internal
