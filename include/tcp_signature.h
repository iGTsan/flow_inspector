#pragma once

#include <iostream>
#include <sstream>
#include <memory>
#include <pcap.h>
#include "Packet.h"
#include "TcpLayer.h"
#include "internal_structs.h"

namespace flow_inspector::internal {

class TCPSignature : public Signature {
public:
  TCPSignature(uint16_t srcPort, uint16_t dstPort)
      : src_port_(srcPort), dst_port_(dstPort) {}

  bool check(const Packet& packet) const noexcept override {
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

  bool operator==(const Signature& other) const noexcept override {
    const auto* tcp_sig = dynamic_cast<const TCPSignature*>(&other);
    if (!tcp_sig) {
      return false;
    }
    return src_port_ == tcp_sig->src_port_ && dst_port_ == tcp_sig->dst_port_;
  }

  size_t hash() const noexcept override {
    size_t hash_val = 0;
    hash_val ^= src_port_ + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
    hash_val ^= dst_port_ + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
    return hash_val;
  }

  static ::std::unique_ptr<Signature> createTCPSignature(const ::std::string& initString) {
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

    return ::std::make_unique<TCPSignature>(static_cast<uint16_t>(srcPort),
                                            static_cast<uint16_t>(dstPort));
  }

private:
  static ::std::string trim(const ::std::string& str) {
    size_t start = str.find_first_not_of(" \t");
    size_t end = str.find_last_not_of(" \t");
    return (start == ::std::string::npos) ? "" : str.substr(start, end - start + 1);
  }

  uint16_t src_port_;
  uint16_t dst_port_;
};

} // namespace flow_inspector::internal
