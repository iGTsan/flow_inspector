#include <gtest/gtest.h>
#include <pcap.h>
#include "EthLayer.h"
#include "Packet.h"
#include "PayloadLayer.h"
#include "TcpLayer.h"
#include "IPv4Layer.h"
#include "UdpLayer.h"
#include "tcp_signature.h"

namespace {

class TestPacket {
 public:
  ::pcpp::EthLayer eth;
  ::pcpp::IPv4Layer ip;
  ::std::unique_ptr<::pcpp::TcpLayer> tcp;
  ::std::unique_ptr<::pcpp::UdpLayer> udp;
  ::std::unique_ptr<::pcpp::PayloadLayer> payload;
  ::pcpp::Packet pkt{100};

  static TestPacket createTcp(uint16_t src, uint16_t dst) {
    TestPacket tp {
      .eth = ::pcpp::EthLayer(::pcpp::MacAddress("aa:bb:cc:dd:ee:ff"), ::pcpp::MacAddress("ff:ee:dd:cc:bb:aa")),
      .ip = ::pcpp::IPv4Layer(::pcpp::IPv4Address("192.168.1.1"), ::pcpp::IPv4Address("192.168.1.2")),
      .tcp = ::std::make_unique<::pcpp::TcpLayer>(src, dst),
    };
    tp.pkt.addLayer(&tp.eth);
    tp.pkt.addLayer(&tp.ip);
    tp.pkt.addLayer(tp.tcp.get());
    tp.pkt.computeCalculateFields();
    return tp;
  }
  static TestPacket createTcpWithAnyPayload(uint16_t src, uint16_t dst, const ::std::string& payload_str) {
    TestPacket tp = createTcp(src, dst);
    tp.payload = ::std::make_unique<::pcpp::PayloadLayer>(
        reinterpret_cast<const ::uint8_t*>(payload_str.data()), payload_str.size());
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

TEST(TCPSignature, SrcAndDstMatch) {
  uint16_t src = 1234, dst = 80;
  auto tpacket = ::TestPacket::createTcp(src, dst);
  TCPSignature sig(src, dst);
  EXPECT_TRUE(sig.check(tpacket.toPacket()));
}

TEST(TCPSignature, OnlySrcMatch) {
  uint16_t src = 1234, dst = 80;
  auto tpacket = ::TestPacket::createTcp(src, 9999);
  TCPSignature sig(src, 0);  // 0 = любой dst
  EXPECT_TRUE(sig.check(tpacket.toPacket()));
}

TEST(TCPSignature, OnlyDstMatch) {
  uint16_t src = 1234, dst = 80;
  auto tpacket = ::TestPacket::createTcp(4321, dst);
  TCPSignature sig(0, dst);  // 0 = любой src
  EXPECT_TRUE(sig.check(tpacket.toPacket()));
}

TEST(TCPSignature, NoMatch) {
  uint16_t src = 1234, dst = 80;
  auto tpacket = ::TestPacket::createTcp(2222, 3333);
  TCPSignature sig(src, dst);
  EXPECT_FALSE(sig.check(tpacket.toPacket()));
}

TEST(TCPSignature, AnyAnyMatch) {
  auto tpacket = ::TestPacket::createTcp(11, 22);
  TCPSignature sig(0, 0);  // 0 = любой порт
  EXPECT_TRUE(sig.check(tpacket.toPacket()));
}

} // namespace flow_inspector::internal
