#include <string>
#include <sstream>
#include <memory>
#include <unordered_set>
#include <regex>

#include <pcap.h>

#include "Packet.h"
#include "TcpLayer.h"
#include "UdpLayer.h"

#include "content_signature.h"
#include "internal_structs.h"


namespace flow_inspector::internal {


ContentSignature::Protocols ContentSignature::stringToProto(const ::std::string& proto) noexcept {
  if (proto == "udp") {
    return Protocols::UDP;
  }
  if (proto == "tcp") {
    return Protocols::TCP;
  }
  if (proto == "http") {
    return Protocols::HTTP;
  }
  VERIFY(false, "Unknown protocol");
}

ContentSignature::ContentSignature(
    const ::std::string& protocol,
    const ::std::string& content,
    const ::std::unordered_set<::std::string>& flags) noexcept
  : protocol_(stringToProto(protocol)), content_(content), flags_(flags) {
      if (flags_.count("nocase")) {
          regex_flags_ = ::std::regex_constants::icase;
      }
  }

bool ContentSignature::check(const Packet& packet) const noexcept {
  ::std::string packet_data;

  switch (protocol_) {
    case Protocols::TCP:
      if (!extractTcpPayload(packet, packet_data)) {
        return false;
      }
      break;
    case Protocols::UDP:
      if (!extractUdpPayload(packet, packet_data)) {
        return false;
      }
      break;
    default:
      return false;
  }
  return packet_data.find(content_) != ::std::string::npos;
}

bool ContentSignature::operator==(const Signature& other) const noexcept {
  const auto* content_sig = dynamic_cast<const ContentSignature*>(&other);
  if (!content_sig) {
    return false;
  }
  return (protocol_ == content_sig->protocol_ &&
      content_ == content_sig->content_ &&
      flags_ == content_sig->flags_);
}

size_t ContentSignature::hash() const noexcept {
  size_t hash_val = protocol_ ^ ::std::hash<::std::string>{}(content_);
  for (const auto& flag : flags_) {
      hash_val ^= ::std::hash<::std::string>{}(flag);
  }
  return hash_val;
}

::std::unique_ptr<Signature> ContentSignature::createContentSignature(
    const ::std::string& initString) noexcept {
  ::std::istringstream stream(initString);
  ::std::string protocol, content, flagStr;

  ::std::getline(stream, protocol, ',');
  protocol = trim(protocol);

  ::std::getline(stream, content, ',');
  content = trim(content);

  ::std::unordered_set<::std::string> flags;
  while (::std::getline(stream, flagStr, ',')) {
    flagStr = trim(flagStr);
    if (!flagStr.empty()) {
      flags.insert(flagStr);
    }
  }

  return ::std::make_unique<ContentSignature>(protocol, content, flags);
}

bool ContentSignature::extractTcpPayload(const Packet& packet, ::std::string& payload) const noexcept {
  const auto& pcpp_packet = packet.getParsedPacket();
  const auto tcp_layer = pcpp_packet.getLayerOfType<::pcpp::TcpLayer>();
  if (!tcp_layer) {
    return false;
  }
  payload = ::std::string(
      reinterpret_cast<const char*>(tcp_layer->getLayerPayload()), tcp_layer->getLayerPayloadSize());
  return true;
}

bool ContentSignature::extractUdpPayload(const Packet& packet, ::std::string& payload) const noexcept {
  const auto& pcpp_packet = packet.getParsedPacket();
  const auto udp_layer = pcpp_packet.getLayerOfType<::pcpp::UdpLayer>();
  if (!udp_layer) {
    return false;
  }
  payload = ::std::string(
      reinterpret_cast<const char*>(udp_layer->getLayerPayload()), udp_layer->getLayerPayloadSize());
  return true;
}

}  // namespace flow_inspector::internal
