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


namespace flow_inspector::internal {


class RawBytesSignature: public Signature {
 public:
  RawBytesSignature(::std::vector<byte> payload) noexcept
    : payload_(::std::move(payload))
  {
    payload_.print();
  }

  RawBytesSignature(::std::vector<byte> payload, const uint32_t payload_offset) noexcept
    : payload_(::std::move(payload))
    , payload_offset_(payload_offset)
  {
    payload_.print();
  }

  bool check(const Packet& packet) const noexcept {
    // coutDebug() << "Checking signature ";
    // payload_.print();
    // if (packet.signatures.contains(this)) {
    //   return true;
    // }
    const u_char* packetData = packet.packet.getRawData();
    size_t packetSize = packet.packet.getRawDataLen();
    
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
    coutDebug() << "Result is: " << result << std::endl;
    return result;
  }

  bool operator==(const Signature& other) const noexcept {
    if (payload_offset_ != other.payload_offset_) {
      return false;
    }
    return payload_ == other.payload_;
  }

private:
  template <typename T>
  friend struct ::std::hash;

  ByteVector payload_;
  ::std::optional<uint32_t> payload_offset_;
};


}  // namespace flow_inspector::internal
