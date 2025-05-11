#include <iostream>
#include <unordered_set>
#include <sstream>
#include <memory>

#include <pcap.h>
#include "IPv4Layer.h"
#include "Packet.h"

#include "internal_structs.h"
#include "ip_signature.h"


namespace flow_inspector::internal {


uint32_t swapOctets(uint32_t ip) noexcept {
  return ((ip & 0x000000FF) << 24) |
      ((ip & 0x0000FF00) << 8)  |
      ((ip & 0x00FF0000) >> 8)  |
      ((ip & 0xFF000000) >> 24);
}

uint32_t getNetworkAddress(uint32_t ip, int maskLength) noexcept {
    uint32_t mask = (~0u) << (32 - maskLength);
    return ip & mask;
}

uint32_t getMaskByLen(int maskLength) noexcept {
    return (~0u) << (32 - maskLength);
}

uint32_t ipToUInt(const ::std::string& ipStr) noexcept {
    ::pcpp::IPv4Address ip(ipStr);
    return swapOctets(ip.toInt());
}

::std::string adressToString(uint32_t ip, int maskLength) noexcept {
  ::std::ostringstream ss;

  uint8_t octet1 = (ip >> 24) & 0xFF;
  uint8_t octet2 = (ip >> 16) & 0xFF;
  uint8_t octet3 = (ip >> 8) & 0xFF;
  uint8_t octet4 = ip & 0xFF;

  ss << static_cast<int>(octet1) << "."
     << static_cast<int>(octet2) << "."
     << static_cast<int>(octet3) << "."
     << static_cast<int>(octet4) << "/"
     << maskLength;

  return ss.str();
}


IPSignature::IPSignature(const ::std::unordered_set<::std::pair<uint32_t, uint32_t>>& srcIpMasks,
    const ::std::unordered_set<::std::pair<uint32_t, uint32_t>>& dstIpMasks)  noexcept
  : src_ip_masks_(srcIpMasks.begin(), srcIpMasks.end())
  , dst_ip_masks_(dstIpMasks.begin(), dstIpMasks.end()) {}

bool IPSignature::check(const Packet& packet) const noexcept {
  const auto& pcpp_packet = packet.getParsedPacket();
  const auto ip_layer = pcpp_packet.getLayerOfType<pcpp::IPv4Layer>();
  if (!ip_layer) {
    return false;
  }

  uint32_t srcIp = swapOctets(ip_layer->getSrcIPv4Address().toInt());
  uint32_t dstIp = swapOctets(ip_layer->getDstIPv4Address().toInt());

  bool src_match = src_ip_masks_.empty() || matchIPWithMasks(srcIp, src_ip_masks_);
  bool dst_match = dst_ip_masks_.empty() || matchIPWithMasks(dstIp, dst_ip_masks_);

  return src_match && dst_match;
}

bool IPSignature::operator==(const Signature& other) const noexcept {
  const auto* ip_sig = dynamic_cast<const IPSignature*>(&other);
  if (!ip_sig) {
    return false;
  }
  return src_ip_masks_ == ip_sig->src_ip_masks_ && dst_ip_masks_ == ip_sig->dst_ip_masks_;
}

size_t IPSignature::hash() const noexcept {
  size_t hash_val = 0;
  for (const auto& [ip, mask] : src_ip_masks_) {
    hash_val ^= ip + mask + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
  }
  for (const auto& [ip, mask] : dst_ip_masks_) {
    hash_val ^= ip + mask + 0x9e3779b9 + (hash_val << 6) + (hash_val >> 2);
  }
  return hash_val;
}

::std::unique_ptr<Signature> IPSignature::createIPSignature(
    const ::std::string& initString) noexcept {
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> src_ip_masks;
  ::std::unordered_set<::std::pair<uint32_t, uint32_t>> dst_ip_masks;

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
    srcIpStr = trim(srcIpStr);
    if (srcIpStr == "$HOME_NET") {
      srcIpStr = HOME_NET_ADDR;
    }
    if (srcIpStr == "any") {
      continue;
    }
    auto pos = srcIpStr.find('/');

    ::std::string ipPart;
    int mask = 32;

    if (pos != ::std::string::npos) {
      ipPart = srcIpStr.substr(0, pos);
      ::std::string maskStr = srcIpStr.substr(pos + 1);
      safeStringToInt(maskStr, mask);
    } else {
      ipPart = srcIpStr;
    }

    src_ip_masks.insert({ipToUInt(ipPart), getMaskByLen(mask)});
  }
  
  ::std::string dstIpStr;
  while (::std::getline(dstStream, dstIpStr, ',')) {
    dstIpStr = trim(dstIpStr);
    if (dstIpStr == "$HOME_NET") {
      dstIpStr = HOME_NET_ADDR;
    }
    if (dstIpStr == "any") {
      continue;
    }
    auto pos = dstIpStr.find('/');

    ::std::string ipPart;
    int mask = 32;

    if (pos != ::std::string::npos) {
      ipPart = dstIpStr.substr(0, pos);
      ::std::string maskStr = dstIpStr.substr(pos + 1);
      safeStringToInt(maskStr, mask);
    } else {
      ipPart = dstIpStr;
    }

    dst_ip_masks.insert({ipToUInt(ipPart), getMaskByLen(mask)});
  }

  return ::std::make_unique<IPSignature>(src_ip_masks, dst_ip_masks);
}

bool IPSignature::matchIPWithMasks(
    uint32_t ip, const ::std::vector<::std::pair<uint32_t, uint32_t>>& ipMasks) const noexcept {
  for (const auto& [networkIp, mask] : ipMasks) {
    if ((ip & mask) == networkIp) {
      return true;
    }
  }
  return false;
}


} // namespace flow_inspector::internal
