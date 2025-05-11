#include <sstream>
#include <memory>

#include <pcap.h>
#include "Packet.h"
#include "TcpLayer.h"

#include "internal_structs.h"
#include "tcp_signature.h"


namespace flow_inspector::internal {


TCPSignature::TCPSignature(uint16_t srcPort, uint16_t dstPort) noexcept
    : src_port_(srcPort), dst_port_(dstPort) {}

bool TCPSignature::check(const Packet& packet) const noexcept {
  const auto& pcpp_packet = packet.getParsedPacket();
  const auto tcp_layer = pcpp_packet.getLayerOfType<::pcpp::TcpLayer>();
  if (!tcp_layer) {
    return false;
  }

  uint16_t srcPort = ntohs(tcp_layer->getTcpHeader()->portSrc);
  uint16_t dstPort = ntohs(tcp_layer->getTcpHeader()->portDst);

  bool src_match = (src_port_ == 0) || (srcPort == src_port_);
  bool dst_match = (dst_port_ == 0) || (dstPort == dst_port_);

  return src_match && dst_match;
}

bool TCPSignature::operator==(const Signature& other) const noexcept {
  const auto* tcp_sig = dynamic_cast<const TCPSignature*>(&other);
  if (!tcp_sig) {
    return false;
  }
  return src_port_ == tcp_sig->src_port_ && dst_port_ == tcp_sig->dst_port_;
}

size_t TCPSignature::hash() const noexcept {
  size_t hash_val = 0;
  hash_val ^= src_port_ + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
  hash_val ^= dst_port_ + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
  return hash_val;
}

::std::unique_ptr<Signature> TCPSignature::createTCPSignature(const ::std::string& initString) noexcept {
  ::std::istringstream stream(initString);
  ::std::string srcPortStr, dstPortStr, tmp;

  ::std::getline(stream, tmp, '[');
  ::std::getline(stream, srcPortStr, ']');
  ::std::getline(stream, tmp, '[');
  ::std::getline(stream, dstPortStr, ']');

  srcPortStr = trim(srcPortStr);
  dstPortStr = trim(dstPortStr);

  int srcPort = 0, dstPort = 0;
  if (!srcPortStr.empty() && srcPortStr != "any")
    safeStringToInt(srcPortStr, srcPort);
  if (!dstPortStr.empty() && dstPortStr != "any")
    safeStringToInt(dstPortStr, dstPort);

  return ::std::make_unique<TCPSignature>(
      static_cast<uint16_t>(srcPort), static_cast<uint16_t>(dstPort));
}

::std::string TCPSignature::trim(const ::std::string& str) noexcept {
  size_t start = str.find_first_not_of(" \t");
  size_t end = str.find_last_not_of(" \t");
  return (start == ::std::string::npos) ? "" : str.substr(start, end - start + 1);
}


} // namespace flow_inspector::internal
