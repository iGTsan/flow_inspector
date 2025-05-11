#include "gtest/gtest.h"
#include <gtest/gtest.h>

#include <pcap.h>

#include "EthLayer.h"
#include "IPv4Layer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

#include "content_signature.h"


namespace {

class TestPacket {
  public:
  ::pcpp::EthLayer eth;
  ::pcpp::IPv4Layer ip;
  ::std::unique_ptr<::pcpp::TcpLayer> tcp;
  ::std::unique_ptr<::pcpp::UdpLayer> udp;
  ::std::unique_ptr<::pcpp::PayloadLayer> payload;
  ::pcpp::Packet pkt{100};

  static TestPacket createTcpWithPayload(const ::std::string& payload_str) {
    TestPacket tp {
      .eth = ::pcpp::EthLayer(::pcpp::MacAddress("aa:bb:cc:dd:ee:ff"), ::pcpp::MacAddress("ff:ee:dd:cc:bb:aa")),
      .ip = ::pcpp::IPv4Layer(::pcpp::IPv4Address("192.168.1.1"), ::pcpp::IPv4Address("192.168.1.2")),
      .tcp = ::std::make_unique<::pcpp::TcpLayer>(1234, 80),
      .payload = ::std::make_unique<::pcpp::PayloadLayer>(
          reinterpret_cast<const ::uint8_t*>(payload_str.data()), payload_str.size()),
    };
    tp.pkt.addLayer(&tp.eth);
    tp.pkt.addLayer(&tp.ip);
    tp.pkt.addLayer(tp.tcp.get());
    tp.pkt.addLayer(tp.payload.get());
    tp.pkt.computeCalculateFields();
    return tp;
  }

  static TestPacket createUdpWithPayload(const ::std::string& payload_str) {
    TestPacket tp {
      .eth = ::pcpp::EthLayer(::pcpp::MacAddress("aa:bb:cc:dd:ee:ff"), ::pcpp::MacAddress("ff:ee:dd:cc:bb:aa")),
      .ip = ::pcpp::IPv4Layer(::pcpp::IPv4Address("192.168.1.1"), ::pcpp::IPv4Address("192.168.1.2")),
      .udp = ::std::make_unique<::pcpp::UdpLayer>(1234, 5353),
      .payload = ::std::make_unique<::pcpp::PayloadLayer>(
          reinterpret_cast<const ::uint8_t*>(payload_str.data()), payload_str.size()),
    };
    tp.pkt.addLayer(&tp.eth);
    tp.pkt.addLayer(&tp.ip);
    tp.pkt.addLayer(tp.udp.get());
    tp.pkt.addLayer(tp.payload.get());
    tp.pkt.computeCalculateFields();
    return tp;
  }

  ::flow_inspector::internal::Packet toPacket() {
    return ::flow_inspector::internal::Packet{*pkt.getRawPacket(), true};
  }
};

} // namespace


namespace flow_inspector::internal {


TEST(ContentSignature, TcpPositive) {
  auto tpacket = ::TestPacket::createTcpWithPayload("HelloWorld");
  ::std::unordered_set<::std::string> flags;
  ::flow_inspector::internal::ContentSignature sig("tcp", "HelloWorld", flags);
  EXPECT_TRUE(sig.check(tpacket.toPacket()));
}

TEST(ContentSignature, TcpNegative) {
  auto tpacket = ::TestPacket::createTcpWithPayload("FooBar");
  ::std::unordered_set<::std::string> flags;
  ::flow_inspector::internal::ContentSignature sig("tcp", "World", flags);
  EXPECT_FALSE(sig.check(tpacket.toPacket()));
}

TEST(ContentSignature, UdpPositive) {
  auto tpacket = ::TestPacket::createUdpWithPayload("TestUDPpayload");
  ::std::unordered_set<::std::string> flags;
  ::flow_inspector::internal::ContentSignature sig("udp", "UDP", flags);
  EXPECT_TRUE(sig.check(tpacket.toPacket()));
}

TEST(ContentSignature, UdpNegative) {
  auto tpacket = ::TestPacket::createUdpWithPayload("UDPdataHERE");
  ::std::unordered_set<::std::string> flags;
  ::flow_inspector::internal::ContentSignature sig("udp", "notInPayload", flags);
  EXPECT_FALSE(sig.check(tpacket.toPacket()));
}


}  // namespace flow_inspector::internal
