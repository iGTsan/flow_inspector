#pragma once

#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <fstream>
#include <queue>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <chrono>
#include <optional>
#include <cstdint>
#include <span>
#include <cstdlib>
#include <unordered_set>

#include <pcap.h>
#include "Packet.h"

#include "RawPacket.h"
#include "internal_structs.h"
#include "signature_factory.h"


namespace flow_inspector::internal {


class RawBytesSignature: public Signature {
 public:
  RawBytesSignature(
      ::std::vector<byte> payload, ::std::optional<uint32_t> offset = ::std::nullopt) noexcept
    : payload_(::std::move(payload))
    , payload_offset_(offset)
  {
    payload_.print();
  }

  bool check(const Packet& packet) const noexcept override {
    // coutDebug() << "Checking signature ";
    // payload_.print();
    // if (packet.signatures.contains(this)) {
    //   return true;
    // }
    const u_char* packetData = packet.packet->getRawData();
    size_t packetSize = packet.packet->getRawDataLen();
    
    // Проверка с учетом смещения
    if (payload_offset_) {
      size_t offset = *payload_offset_;
      size_t payloadSize = payload_->size();
      if (offset + payloadSize <= packetSize) {
        return ::std::equal(payload_->begin(), payload_->end(), packetData + offset);
      }
      return false;
    }
  
    // Поиск без смещения
    auto it = ::std::search(packetData, packetData + packetSize, payload_->begin(), payload_->end());
    bool result = (it != packetData + packetSize);
    coutDebug() << "Result is: " << result << ::std::endl;
    return result;
  }

  bool operator==(const Signature& other) const noexcept override {
    const auto* rb_sig = dynamic_cast<const RawBytesSignature*>(&other);
    if (!rb_sig) {
      return false;
    }
    if (payload_offset_ != rb_sig->payload_offset_) {
      return false;
    }
    return payload_ == rb_sig->payload_;
  }

  size_t hash() const noexcept override {
    return ::std::hash<ByteVector>{}(payload_) ^
        (::std::hash<::std::optional<uint32_t>>{}(payload_offset_) << 1);
  }

  // parses the rules that satisfy the following pattern
  // event; name; signature1; signature2 ...
  // where event is a member of ::flow_inspector::internal::Event::EventType
  // signature1 is raw_bytes(payload, offset) or just (payload)
  // payload is a vector bytes [1 2 3...], offset is a uint32_t
  static ::std::unique_ptr<Signature> createRawBytesSignature(const ::std::string& initString) {
    ::std::istringstream stream(initString);
    ::std::string dataString, offsetString;
    ::std::getline(stream, dataString, ',');
    ::std::vector<byte> payload;
    dataString.erase(0, dataString.find('[') + 1);
    dataString.erase(dataString.find(']'));
    ::std::istringstream dataStream(dataString);
    int byteValue;
    while (dataStream >> byteValue) {
      payload.push_back(static_cast<byte>(byteValue));
    }
  
    ::std::optional<uint32_t> offset = ::std::nullopt;
    if (std::getline(stream, offsetString, ',')) {
      offset = ::std::stoi(offsetString);
    }
  
    return ::std::make_unique<RawBytesSignature>(payload, offset);
  }

private:
  ByteVector payload_;
  ::std::optional<uint32_t> payload_offset_;
};


}  // namespace flow_inspector::internal
