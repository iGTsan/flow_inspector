#pragma once

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


namespace flow_inspector::internal {


using byte = uint8_t;


struct Packet {
  Packet(const ::std::vector<byte>& data) noexcept
    : bytes_{data}
  {}

  ::std::string toString() const noexcept {
    ::std::stringstream ss;
    ss << "[";
    for (auto it = bytes_.begin(); it != bytes_.end(); ++it) {
      if (it != bytes_.begin()) {
        ss << " ";
      }
      ss << static_cast<int>(*it);
    }
    ss << "]";
    return ss.str();
  }

  ::std::vector<byte> bytes_;
};


class Alert {
public:
  Alert(const ::std::string& message) noexcept
    : message_{message}
  {}

  ::std::string toString() const noexcept {
    return message_;
  }

private:
  ::std::string message_;
};


// время, пакет, предупреждение (опционально)
struct LogEntry {
  const ::std::time_t timestamp;
  ::std::shared_ptr<const Packet> packet;
  ::std::shared_ptr<const Alert> alert;
};


class Rule {};


class Signature {
  public:
    Signature(const ::std::vector<byte>& payload) noexcept
      : payload_(payload)
    {}

    Signature(const ::std::vector<byte>& payload, const uint32_t payload_offset) noexcept
      : payload_(payload)
      , payload_offset_(payload_offset)
    {}

    bool Check(const Packet& packet) const noexcept {
      if (payload_offset_) {
        return *payload_offset_ + payload_.size() <= packet.bytes_.size() &&
          ::std::equal(payload_.begin(), payload_.end(), packet.bytes_.begin() + *payload_offset_);
      }
      return ::std::search(packet.bytes_.begin(), packet.bytes_.end(),
        payload_.begin(), payload_.end()) != packet.bytes_.end();
    }

  private:
    ::std::vector<byte> payload_;
    ::std::optional<uint32_t> payload_offset_;
};


class Event {};


}  // namespace flow_inspector::internal