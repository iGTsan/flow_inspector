#pragma once

#include <iostream>
#include <unordered_set>
#include <pcap.h>
#include "IPv4Layer.h"
#include "Packet.h"
#include "IpAddress.h"
#include "internal_structs.h"

namespace flow_inspector::internal {

class IPSignature: public Signature {
 public:
  IPSignature(::std::unordered_set<::pcpp::IPv4Address> srcIpSet,
      ::std::unordered_set<::pcpp::IPv4Address> dstIpSet)
    : src_ip_set_(::std::move(srcIpSet)), dst_ip_set_(::std::move(dstIpSet)) {}

  bool check(const Packet& packet) const noexcept override {
    const auto& pcpp_packet = packet.parsed_packet;
    const auto ip_layer = pcpp_packet.getLayerOfType<::pcpp::IPv4Layer>();
    if (!ip_layer) {
      return false;
    }

    const auto& srcIp = ip_layer->getSrcIPv4Address();
    const auto& dstIp = ip_layer->getDstIPv4Address();

    bool src_match = src_ip_set_.empty() || src_ip_set_.count(srcIp) > 0;
    bool dst_match = dst_ip_set_.empty() || dst_ip_set_.count(dstIp) > 0;

    if (src_match && dst_match) {
      return true;
    }
    return false;
  }

  bool operator==(const Signature& other) const noexcept override {
    const auto* ip_sig = dynamic_cast<const IPSignature*>(&other);
    if (!ip_sig) {
      return false;
    }
    return src_ip_set_ == ip_sig->src_ip_set_ && dst_ip_set_ == ip_sig->dst_ip_set_;
  }

  size_t hash() const noexcept override {
    size_t hash_val = 0;
    for (const auto& ip : src_ip_set_) {
      hash_val ^= ip.toInt() + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
    }
    for (const auto& ip : dst_ip_set_) {
      hash_val ^= ip.toInt() + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
    }
    return hash_val;
  }

  static ::std::unique_ptr<Signature> createIPSignature(const ::std::string& initString) {
    ::std::unordered_set<::pcpp::IPv4Address> src_ips;
    ::std::unordered_set<::pcpp::IPv4Address> dst_ips;

    ::std::istringstream stream(initString);
    ::std::string srcSegment, dstSegment, tmp;

    ::std::getline(stream, tmp, '[');
    ::std::getline(stream, srcSegment, ']');
    ::std::getline(stream, tmp, '[');
    ::std::getline(stream, dstSegment, ']');

    ::std::istringstream srcStream(srcSegment);
    ::std::istringstream dstStream(dstSegment);

    ::std::string srcIpStr;
    while (::std::getline(srcStream, srcIpStr, ',')) {
      src_ips.insert(::pcpp::IPv4Address(trim(srcIpStr)));
    }

    ::std::string dstIpStr;
    while (::std::getline(dstStream, dstIpStr, ',')) {
      dst_ips.insert(::pcpp::IPv4Address(trim(dstIpStr)));
    }

    return ::std::make_unique<IPSignature>(src_ips, dst_ips);
  }

 private:
  ::std::unordered_set<::pcpp::IPv4Address> src_ip_set_;
  ::std::unordered_set<::pcpp::IPv4Address> dst_ip_set_;
};

} // namespace flow_inspector::internal
