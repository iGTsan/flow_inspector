#pragma once

#include <cstring>
#include <vector>
#include <string>
#include <ctime>
#include <memory>
#include <optional>
#include <cstdint>
#include <cstdlib>

#include <pcap.h>

#include "internal_structs.h"


namespace flow_inspector::internal {


class RawBytesSignature: public Signature {
 public:
  RawBytesSignature(
      ::std::vector<byte> payload, ::std::optional<uint32_t> offset = ::std::nullopt) noexcept;

  bool check(const Packet& packet) const noexcept override;

  bool operator==(const Signature& other) const noexcept override;

  size_t hash() const noexcept override;

  // parses the rules that satisfy the following pattern
  // event; name; signature1; signature2 ...
  // where event is a member of ::flow_inspector::internal::Event::EventType
  // signature1 is raw_bytes(payload, offset) or just (payload)
  // payload is a vector bytes [1 2 3...], offset is a uint32_t
  static ::std::unique_ptr<Signature> createRawBytesSignature(const ::std::string& initString) noexcept;

 private:
  ByteVector payload_;
  ::std::optional<uint32_t> payload_offset_;
};


}  // namespace flow_inspector::internal
