#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <ctime>
#include <memory>
#include <optional>
#include <cstdint>
#include <span>
#include <cstdlib>

#include <pcap.h>

#include "RawPacket.h"

#include "debug_logger.h"
#include "internal_structs.h"
#include "raw_bytes_signature.h"


namespace flow_inspector::internal {


RawBytesSignature::RawBytesSignature(::std::vector<byte> payload, ::std::optional<uint32_t> offset) noexcept
  : payload_(::std::move(payload))
  , payload_offset_(offset)
{
  payload_.print();
}

bool RawBytesSignature::check(const Packet& packet) const noexcept {
  const u_char* packetData = packet.packet->getRawData();
  size_t packetSize = packet.packet->getRawDataLen();

  if (payload_offset_) {
    size_t offset = *payload_offset_;
    size_t payloadSize = payload_->size();
    if (offset + payloadSize <= packetSize) {
      return ::std::equal(payload_->begin(), payload_->end(), packetData + offset);
    }
    return false;
  }

  auto it = ::std::search(packetData, packetData + packetSize, payload_->begin(), payload_->end());
  bool result = (it != packetData + packetSize);
  coutDebug() << "Result is: " << result << ::std::endl;
  return result;
}

bool RawBytesSignature::operator==(const Signature& other) const noexcept {
  const auto* rb_sig = dynamic_cast<const RawBytesSignature*>(&other);
  if (!rb_sig) {
    return false;
  }
  if (payload_offset_ != rb_sig->payload_offset_) {
    return false;
  }
  return payload_ == rb_sig->payload_;
}

size_t RawBytesSignature::hash() const noexcept {
  return ::std::hash<ByteVector>{}(payload_) ^
      (::std::hash<::std::optional<uint32_t>>{}(payload_offset_) << 1);
}

::std::unique_ptr<Signature> RawBytesSignature::createRawBytesSignature(
    const ::std::string& initString) noexcept {
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


}  // namespace flow_inspector::internal
